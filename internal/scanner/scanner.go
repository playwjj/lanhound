// Package scanner is LanHound's discovery engine. For each interface
// with a private IPv4 subnet it keeps one raw socket open, listens to
// ARP/DHCP/mDNS/SSDP/NetBIOS chatter continuously, and politely
// ARP-sweeps the subnet on a fixed interval. Interfaces that appear or
// disappear (Wi-Fi reconnects, a new DHCP lease) are followed
// automatically.
//
// It only ever sends ordinary ARP requests from the host's own IP/MAC.
// No spoofing, no gratuitous ARP, no countermeasures — a sentinel,
// not a soldier.
package scanner

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/arp"
	"github.com/playwjj/lanhound/internal/logx"
	"github.com/playwjj/lanhound/internal/netutil"
	"github.com/playwjj/lanhound/internal/passive"
)

// link is a raw Ethernet socket bound to one interface.
type link interface {
	// Read returns one frame; outgoing reports frames the host itself
	// sent. It returns errTimeout periodically so callers can stop.
	Read(buf []byte) (n int, outgoing bool, err error)
	Write(frame []byte) error
	Close() error
}

var errTimeout = errors.New("read timeout")

// Swapped out in tests.
var (
	openLinkFunc = openLink
	targetsFunc  = netutil.Targets
)

// refreshEvery is how often the interface list is re-read.
const refreshEvery = 30 * time.Second

// Config controls an Engine. Zero values get sensible defaults.
type Config struct {
	Interval time.Duration // between ARP sweeps (default 5m)
	Window   time.Duration // listen time after the last request of a sweep (default 6s)
	Rate     int           // ARP requests per second per interface (default 300)
	Only     []string      // restrict to these interface names (default: all)
	// DHCPProbeEvery is how often a DHCPDISCOVER is broadcast to find
	// the DHCP servers on each segment (default 30m; negative disables).
	DHCPProbeEvery time.Duration

	// OnSighting receives every device sighting. It is called from
	// several goroutines and must be safe for concurrent use.
	OnSighting func(passive.Sighting)
	// OnStatus is called whenever an interface's status changes.
	OnStatus func()
}

// Status describes one scanned interface for the UI.
type Status struct {
	Interface   string    `json:"interface"`
	Network     string    `json:"network"`
	IP          string    `json:"ip"`
	MAC         string    `json:"mac"`
	Shim        string    `json:"shim,omitempty"` // macvlan interface the sweep is sent from
	Hosts       int       `json:"hosts"`
	Sweeping    bool      `json:"sweeping"`
	LastSweep   time.Time `json:"lastSweep"`
	LastReplies int       `json:"lastReplies"`
	Error       string    `json:"error,omitempty"`
}

// Engine runs one worker per scannable interface.
type Engine struct {
	cfg Config

	mu      sync.Mutex
	workers map[string]*worker
	skipped []string

	firstRound chan struct{}
}

// New returns an Engine; call Run to start it.
func New(cfg Config) *Engine {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Window <= 0 {
		cfg.Window = 6 * time.Second
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 300
	}
	if cfg.DHCPProbeEvery == 0 {
		cfg.DHCPProbeEvery = 30 * time.Minute
	}
	if cfg.OnSighting == nil {
		cfg.OnSighting = func(passive.Sighting) {}
	}
	if cfg.OnStatus == nil {
		cfg.OnStatus = func() {}
	}
	return &Engine{cfg: cfg, workers: map[string]*worker{}, firstRound: make(chan struct{})}
}

// FirstRound is closed once every interface present at startup has
// completed its first sweep (or failed to open).
func (e *Engine) FirstRound() <-chan struct{} { return e.firstRound }

// Run follows the host's interfaces until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	initial := e.refresh(ctx)
	go func() {
		for _, w := range initial {
			select {
			case <-w.firstDone:
			case <-ctx.Done():
				return
			}
		}
		close(e.firstRound)
	}()

	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			for _, w := range e.workers {
				w.stop()
			}
			e.mu.Unlock()
			return
		case <-t.C:
			e.refresh(ctx)
		}
	}
}

// refresh starts workers for new targets and stops vanished ones. It
// returns the workers it started.
func (e *Engine) refresh(ctx context.Context) []*worker {
	targets, skipped := targetsFunc(e.cfg.Only)
	seen := map[string]bool{}
	var started []*worker
	changed := false

	e.mu.Lock()
	e.skipped = skipped
	for _, t := range targets {
		if !e.allowed(t.Iface.Name) {
			continue
		}
		key := t.Iface.Name + "|" + t.Network.String() + "|" + t.IP.String()
		if t.Shim != nil {
			key += "|" + t.Shim.Iface.Name
		}
		seen[key] = true
		if _, ok := e.workers[key]; ok {
			continue
		}
		w := newWorker(t, e.cfg)
		e.workers[key] = w
		started = append(started, w)
		if t.Shim != nil {
			lg().Info("watching interface", "iface", t.Iface.Name, "network", t.Network.String(), "hosts", len(t.Hosts), "shim", t.Shim.Iface.Name)
		} else {
			lg().Info("watching interface", "iface", t.Iface.Name, "network", t.Network.String(), "hosts", len(t.Hosts))
		}
		go w.run(ctx)
	}
	for key, w := range e.workers {
		if !seen[key] {
			lg().Info("interface went away", "iface", w.t.Iface.Name, "network", w.t.Network.String())
			w.stop()
			delete(e.workers, key)
			changed = true
		}
	}
	e.mu.Unlock()

	if changed || len(started) > 0 {
		e.cfg.OnStatus()
	}
	return started
}

func (e *Engine) allowed(name string) bool {
	if len(e.cfg.Only) == 0 {
		return true
	}
	for _, n := range e.cfg.Only {
		if n == name {
			return true
		}
	}
	return false
}

// Sweep asks every interface to sweep now instead of waiting for the
// next interval.
func (e *Engine) Sweep() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, w := range e.workers {
		select {
		case w.trigger <- struct{}{}:
		default: // a sweep is already pending
		}
	}
}

// Status reports every interface being watched, sorted by name.
func (e *Engine) Status() []Status {
	e.mu.Lock()
	out := make([]Status, 0, len(e.workers))
	for _, w := range e.workers {
		out = append(out, w.status())
	}
	e.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Network < out[j].Network
	})
	return out
}

// Skipped explains interfaces that were considered but not scanned.
func (e *Engine) Skipped() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.skipped...)
}

// worker owns one interface's socket.
type worker struct {
	t   netutil.Target
	cfg Config

	trigger   chan struct{}
	firstDone chan struct{}
	firstOnce sync.Once
	cancel    context.CancelFunc
	cancelMu  sync.Mutex
	stopped   bool

	mu      sync.Mutex
	st      Status
	replies map[string]bool // MACs that answered during the current sweep
}

func newWorker(t netutil.Target, cfg Config) *worker {
	w := &worker{
		t:         t,
		cfg:       cfg,
		trigger:   make(chan struct{}, 1),
		firstDone: make(chan struct{}),
		st: Status{
			Interface: t.Iface.Name,
			Network:   t.Network.String(),
			IP:        t.IP.String(),
			MAC:       t.Iface.HardwareAddr.String(),
			Hosts:     len(t.Hosts),
		},
	}
	if t.Shim != nil {
		w.st.Shim = t.Shim.Iface.Name
	}
	return w
}

func (w *worker) status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st
}

func (w *worker) update(f func(*Status)) {
	w.mu.Lock()
	f(&w.st)
	w.mu.Unlock()
	w.cfg.OnStatus()
}

func (w *worker) markFirstDone() { w.firstOnce.Do(func() { close(w.firstDone) }) }

func (w *worker) stop() {
	w.cancelMu.Lock()
	defer w.cancelMu.Unlock()
	w.stopped = true
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *worker) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	w.cancelMu.Lock()
	if w.stopped {
		w.cancelMu.Unlock()
		cancel()
		return
	}
	w.cancel = cancel
	w.cancelMu.Unlock()
	defer cancel()
	defer w.markFirstDone()

	var l link
	for {
		var err error
		if l, err = openLinkFunc(w.t.Iface); err == nil {
			break
		}
		failures.Fail(lg(), "open:"+w.t.Iface.Name, "cannot open raw socket", err, "iface", w.t.Iface.Name)
		w.update(func(s *Status) { s.Error = err.Error() })
		w.markFirstDone()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
	defer l.Close()
	w.update(func(s *Status) { s.Error = "" })

	go w.listen(ctx, l)
	sweepLink := l
	if sl := w.openShim(); sl != nil {
		defer sl.Close()
		go w.listen(ctx, sl)
		sweepLink = sl
	}

	timer := time.NewTimer(0) // first sweep right away
	defer timer.Stop()
	var lastDHCPProbe time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.trigger:
		case <-timer.C:
		}
		if w.cfg.DHCPProbeEvery > 0 && time.Since(lastDHCPProbe) >= w.cfg.DHCPProbeEvery {
			lastDHCPProbe = time.Now()
			// Offers arrive during the sweep's listen window.
			if err := l.Write(passive.BuildDHCPDiscover(w.t.Iface.HardwareAddr, rand.Uint32())); err != nil {
				failures.Fail(lg(), "dhcp:"+w.t.Iface.Name, "DHCP probe failed", err, "iface", w.t.Iface.Name)
			}
		}
		w.sweep(ctx, l, sweepLink)
		w.markFirstDone()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(w.cfg.Interval)
	}
}

// openShim opens the target's shim interface, or returns nil when there
// is none or it cannot be opened (the sweep then goes out on the main
// link and simply cannot reach this host's macvlan containers).
func (w *worker) openShim() link {
	if w.t.Shim == nil {
		return nil
	}
	sl, err := openLinkFunc(w.t.Shim.Iface)
	if err != nil {
		failures.Fail(lg(), "open:"+w.t.Shim.Iface.Name, "cannot open shim, sweeping without it", err, "iface", w.t.Iface.Name, "shim", w.t.Shim.Iface.Name)
		return nil
	}
	return sl
}

// sweep ARP-asks every host once through arpLink (the shim when there
// is one), paced at cfg.Rate, then waits cfg.Window for stragglers.
func (w *worker) sweep(ctx context.Context, l, arpLink link) {
	w.mu.Lock()
	w.replies = map[string]bool{}
	w.mu.Unlock()
	w.update(func(s *Status) { s.Sweeping = true })

	// IPv6: one echo to all-nodes per source address; every IPv6 host
	// on the link answers, and the listener records the replies.
	for i, src := range ipv6Sources(w.t.Iface) {
		if err := l.Write(passive.BuildEchoAllNodes(w.t.Iface.HardwareAddr, src, 0x4c48, uint16(i+1))); err != nil {
			failures.Fail(lg(), "echo6:"+w.t.Iface.Name, "IPv6 echo failed", err, "iface", w.t.Iface.Name)
		}
	}

	err := sendRequests(ctx, arpLink, w.t, arpLink != l, w.cfg.Rate)
	if err == nil {
		select {
		case <-ctx.Done():
		case <-time.After(w.cfg.Window):
		}
	}

	w.mu.Lock()
	n := len(w.replies)
	w.replies = nil
	w.mu.Unlock()
	lg().Debug("sweep done", "iface", w.t.Iface.Name, "replies", n, "err", err)
	w.update(func(s *Status) {
		s.Sweeping = false
		if err != nil {
			s.Error = err.Error()
			return
		}
		s.Error = ""
		s.LastSweep = time.Now()
		s.LastReplies = n
	})
}

// listen decodes frames until ctx is done.
func (w *worker) listen(ctx context.Context, l link) {
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		n, outgoing, err := l.Read(buf)
		if err != nil {
			if !errors.Is(err, errTimeout) && ctx.Err() == nil {
				failures.Fail(lg(), "read:"+w.t.Iface.Name, "cannot read from interface", err, "iface", w.t.Iface.Name)
				time.Sleep(time.Second)
			}
			continue
		}
		if outgoing {
			continue // our own requests echoed back by the packet socket
		}
		now := time.Now()
		for _, s := range passive.Decode(buf[:n]) {
			if !w.accept(&s) {
				continue
			}
			s.Iface, s.At = w.t.Iface.Name, now
			if s.Source == passive.SrcARPReply {
				w.mu.Lock()
				if w.replies != nil {
					w.replies[s.MAC.String()] = true
				}
				w.mu.Unlock()
			}
			w.cfg.OnSighting(s)
		}
	}
}

// accept drops sightings of ourselves and of addresses outside this
// interface's subnet (a misconfigured device, or a relayed DHCP packet).
func (w *worker) accept(s *passive.Sighting) bool {
	if len(s.MAC) != 6 || s.MAC[0]&0x01 != 0 || isZero(s.MAC) {
		return false // multicast/broadcast/empty source
	}
	if s.MAC.String() == w.t.Iface.HardwareAddr.String() {
		return false
	}
	if sh := w.t.Shim; sh != nil && s.MAC.String() == sh.Iface.HardwareAddr.String() {
		return false
	}
	if s.IP != nil {
		if s.IP.Equal(w.t.IP) || (w.t.Shim != nil && s.IP.Equal(w.t.Shim.IP)) {
			return false
		}
		if !w.t.Network.Contains(s.IP) {
			s.IP = nil
		}
	}
	return true
}

// ipv6Sources returns the interface's link-local address and its first
// global one: replies come back from the same scope, so asking from both
// collects devices' link-local and global addresses.
func ipv6Sources(iface net.Interface) []net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var ll, global net.IP
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() != nil || ipn.IP.To16() == nil {
			continue
		}
		switch {
		case ipn.IP.IsLinkLocalUnicast() && ll == nil:
			ll = ipn.IP
		case ipn.IP.IsGlobalUnicast() && global == nil:
			global = ipn.IP
		}
	}
	var out []net.IP
	for _, ip := range []net.IP{ll, global} {
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// sendRequests ARP-asks for every host in the target, paced by a ticker,
// from the shim's address when viaShim is set.
func sendRequests(ctx context.Context, l link, t netutil.Target, viaShim bool, ratePerSec int) error {
	srcMAC, srcIP := t.Iface.HardwareAddr, t.IP
	if viaShim {
		srcMAC, srcIP = t.Shim.Iface.HardwareAddr, t.Shim.IP
	}
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSec))
	defer ticker.Stop()
	for _, host := range t.Hosts {
		if host.Equal(srcIP) {
			continue
		}
		frame, err := arp.BuildRequest(srcMAC, srcIP, host)
		if err != nil {
			return err
		}
		if err := l.Write(frame); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}

// Device is one host found by a one-shot Scan.
type Device struct {
	IP        net.IP           `json:"ip"`
	MAC       net.HardwareAddr `json:"mac"`
	Interface string           `json:"interface"`
	Hostname  string           `json:"hostname,omitempty"`
	Via       string           `json:"via"`
}

// Scan sweeps one target once and returns what it found within timeout
// of the last request — the `lanhound scan` command.
func Scan(t netutil.Target, timeout time.Duration, ratePerSec int) ([]Device, error) {
	if ratePerSec <= 0 {
		ratePerSec = 300
	}
	l, err := openLinkFunc(t.Iface)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	var mu sync.Mutex
	found := map[string]*Device{}
	w := newWorker(t, Config{OnStatus: func() {}, OnSighting: func(s passive.Sighting) {
		if s.IP == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		d, ok := found[s.MAC.String()]
		if !ok {
			via := "heard"
			if s.Source == passive.SrcARPReply {
				via = "reply"
			}
			d = &Device{IP: s.IP, MAC: s.MAC, Interface: t.Iface.Name, Via: via}
			found[s.MAC.String()] = d
		}
		if d.Hostname == "" && s.Hostname != "" {
			d.Hostname = s.Hostname
		}
	}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	listen := func(l link) {
		wg.Add(1)
		go func() { defer wg.Done(); w.listen(ctx, l) }()
	}
	listen(l)
	arpLink := l
	if sl := w.openShim(); sl != nil {
		defer sl.Close()
		listen(sl)
		arpLink = sl
	}
	err = sendRequests(ctx, arpLink, t, arpLink != l, ratePerSec)
	if err == nil {
		time.Sleep(timeout)
	}
	cancel()
	wg.Wait()

	out := make([]Device, 0, len(found))
	for _, d := range found {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out, err
}

func ipLess(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	for i := range a4 {
		if a4[i] != b4[i] {
			return a4[i] < b4[i]
		}
	}
	return false
}

// failures collapses errors retried every sweep or read into one line
// each way.
var failures logx.Failures

func lg() *slog.Logger { return logx.L("scanner") }
