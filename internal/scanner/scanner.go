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
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/arp"
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
	targets, skipped := targetsFunc()
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
		seen[key] = true
		if _, ok := e.workers[key]; ok {
			continue
		}
		w := newWorker(t, e.cfg)
		e.workers[key] = w
		started = append(started, w)
		log.Printf("scanner: watching %s %s (%d hosts)", t.Iface.Name, t.Network, len(t.Hosts))
		go w.run(ctx)
	}
	for key, w := range e.workers {
		if !seen[key] {
			log.Printf("scanner: %s %s went away", w.t.Iface.Name, w.t.Network)
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
	return &worker{
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
		log.Printf("scanner: %v", err)
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

	timer := time.NewTimer(0) // first sweep right away
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.trigger:
		case <-timer.C:
		}
		w.sweep(ctx, l)
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

// sweep ARP-asks every host once, paced at cfg.Rate, then waits
// cfg.Window for stragglers.
func (w *worker) sweep(ctx context.Context, l link) {
	w.mu.Lock()
	w.replies = map[string]bool{}
	w.mu.Unlock()
	w.update(func(s *Status) { s.Sweeping = true })

	err := sendRequests(ctx, l, w.t, w.cfg.Rate)
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
				log.Printf("scanner: read %s: %v", w.t.Iface.Name, err)
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
	if s.IP != nil {
		if s.IP.Equal(w.t.IP) {
			return false
		}
		if !w.t.Network.Contains(s.IP) {
			s.IP = nil
		}
	}
	return true
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// sendRequests ARP-asks for every host in the target, paced by a ticker.
func sendRequests(ctx context.Context, l link, t netutil.Target, ratePerSec int) error {
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSec))
	defer ticker.Stop()
	for _, host := range t.Hosts {
		frame, err := arp.BuildRequest(t.Iface.HardwareAddr, t.IP, host)
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
	done := make(chan struct{})
	go func() { w.listen(ctx, l); close(done) }()
	err = sendRequests(ctx, l, t, ratePerSec)
	if err == nil {
		time.Sleep(timeout)
	}
	cancel()
	<-done

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
