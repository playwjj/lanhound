package core

import (
	"context"
	"errors"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/oui"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/store"
)

// ErrNotFound is returned for unknown device IDs.
var ErrNotFound = errors.New("device not found")

// Options configures a Registry.
type Options struct {
	Store    *store.Store
	Hub      *Hub
	Settings *Settings

	// OfflineAfter is how long a device may stay silent before it is
	// considered offline. It should span at least two sweeps.
	OfflineAfter time.Duration
	// Retention is how long history is kept (default 90 days).
	Retention time.Duration
	// AlertDelay holds a new-device alert back so the hostname (DHCP,
	// mDNS, reverse DNS) can arrive first (default 20s).
	AlertDelay time.Duration

	// Resolve looks up a hostname for a silent device; nil disables it.
	Resolve func(ctx context.Context, ip net.IP) (name, source string)
	// Send delivers alerts (default notify.Send).
	Send func(ctx context.Context, s notify.Settings, m notify.Message) error
	// Now is the clock (tests).
	Now func() time.Time
}

// View is a device as the API presents it.
type View struct {
	store.Device
	MACs       []string `json:"macs"`
	Randomized bool     `json:"randomized"`
	// SameNameAs points at an older device with the same hostname: most
	// likely the same phone before it rotated its MAC. The UI offers a
	// one-click merge.
	SameNameAs int64 `json:"sameNameAs,omitempty"`
}

// Patch is a user edit; nil fields are left alone.
type Patch struct {
	Name  *string `json:"name"`
	Note  *string `json:"note"`
	Known *bool   `json:"known"`
}

// AlertStatus reports notification health to the UI.
type AlertStatus struct {
	LastSent  time.Time `json:"lastSent"`
	LastError string    `json:"lastError,omitempty"`
}

const (
	flushEvery   = 15 * time.Second
	reprobeAfter = 6 * time.Hour
	ifaceSticky  = 2 * time.Minute
)

// Registry is the in-memory, write-through device table.
type Registry struct {
	o Options

	mu         sync.Mutex
	devices    map[int64]*store.Device
	macs       map[int64][]string // device → MACs, oldest first
	byMAC      map[string]int64
	dirty      map[int64]bool // last_seen changed, not yet flushed
	ifaceSeen  map[int64]time.Time
	lastProbe  map[int64]time.Time
	pending    map[int64]time.Time // new-device alerts waiting to go out
	baseline   bool
	alertState AlertStatus

	probes chan int64
}

// NewRegistry loads the stored devices. When the database is empty the
// registry starts in baseline mode: devices found during the first
// sweep are recorded without alerting — you do not want 30 "new device"
// messages the minute you install it.
func NewRegistry(o Options) (*Registry, error) {
	if o.Retention <= 0 {
		o.Retention = 90 * 24 * time.Hour
	}
	if o.AlertDelay <= 0 {
		o.AlertDelay = 20 * time.Second
	}
	if o.OfflineAfter <= 0 {
		o.OfflineAfter = 11 * time.Minute
	}
	if o.Send == nil {
		o.Send = notify.Send
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	r := &Registry{
		o:         o,
		devices:   map[int64]*store.Device{},
		macs:      map[int64][]string{},
		byMAC:     map[string]int64{},
		dirty:     map[int64]bool{},
		ifaceSeen: map[int64]time.Time{},
		lastProbe: map[int64]time.Time{},
		pending:   map[int64]time.Time{},
		probes:    make(chan int64, 512),
	}
	devs, macs, err := o.Store.Devices()
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		r.devices[d.ID] = d
		// Refresh vendors when a newer OUI registry ships with the binary.
		if hw, err := net.ParseMAC(d.MAC); err == nil {
			if v := oui.Lookup(hw); v != d.Vendor {
				d.Vendor = v
				if err := o.Store.UpdateDevice(d); err != nil {
					return nil, err
				}
			}
		}
	}
	sort.Slice(macs, func(i, j int) bool { return macs[i].FirstSeen.Before(macs[j].FirstSeen) })
	for _, m := range macs {
		r.byMAC[m.MAC] = m.DeviceID
		r.macs[m.DeviceID] = append(r.macs[m.DeviceID], m.MAC)
	}
	r.baseline = len(devs) == 0
	return r, nil
}

// Baseline reports whether the registry is still in baseline mode.
func (r *Registry) Baseline() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.baseline
}

// EndBaseline switches alerting on. Called once the first sweep of every
// interface has finished.
func (r *Registry) EndBaseline() {
	r.mu.Lock()
	was := r.baseline
	r.baseline = false
	n := len(r.devices)
	r.mu.Unlock()
	if was {
		log.Printf("registry: baseline complete, %d device(s) recorded; alerting on new devices from now on", n)
		r.o.Hub.Publish("baseline", false)
	}
}

// Observe folds one sighting into the device table.
func (r *Registry) Observe(s passive.Sighting) {
	if s.At.IsZero() {
		s.At = r.o.Now()
	}
	mac := s.MAC.String()
	r.mu.Lock()
	defer r.mu.Unlock()

	id, ok := r.byMAC[mac]
	if !ok {
		r.addDevice(s, mac)
		return
	}
	d := r.devices[id]
	changed := false
	if s.At.After(d.LastSeen) {
		d.LastSeen = s.At
		r.dirty[id] = true
	}
	if d.MAC != mac {
		d.MAC, d.Vendor = mac, oui.Lookup(s.MAC)
		changed = true
	}
	if s.Iface != "" && s.Iface != d.Iface && (d.Iface == "" || s.At.Sub(r.ifaceSeen[id]) > ifaceSticky || !d.Online) {
		d.Iface = s.Iface
		changed = true
	}
	if s.Iface == d.Iface {
		r.ifaceSeen[id] = s.At
	}
	if s.IP != nil && s.IP.String() != d.IP {
		if d.IP != "" {
			r.event(id, s.At, store.EventIP, d.IP+" → "+s.IP.String())
		}
		d.IP = s.IP.String()
		changed = true
		r.queueProbe(d)
	}
	if !d.Online {
		d.Online = true
		changed = true
		r.check(r.o.Store.OpenSession(id, s.At))
		r.event(id, s.At, store.EventOnline, d.IP)
	}
	if r.applyHostname(d, s.Hostname, s.HostnameSource, s.At) {
		changed = true
	}
	if s.Model != "" && s.Model != d.Model && (d.Model == "" || s.Source == passive.SrcMDNS) {
		d.Model = s.Model
		changed = true
	}
	if changed {
		delete(r.dirty, id)
		r.check(r.o.Store.UpdateDevice(d))
		r.publish(d)
	}
	if d.Hostname == "" {
		r.queueProbe(d)
	}
}

func (r *Registry) addDevice(s passive.Sighting, mac string) {
	d := &store.Device{
		MAC:       mac,
		Vendor:    oui.Lookup(s.MAC),
		Iface:     s.Iface,
		Online:    true,
		FirstSeen: s.At,
		LastSeen:  s.At,
		Model:     s.Model,
	}
	if s.IP != nil {
		d.IP = s.IP.String()
	}
	if s.Hostname != "" {
		d.Hostname, d.HostnameSource = s.Hostname, s.HostnameSource
	}
	if err := r.o.Store.InsertDevice(d); err != nil {
		log.Printf("registry: insert %s: %v", mac, err)
		return
	}
	r.devices[d.ID] = d
	r.byMAC[mac] = d.ID
	r.macs[d.ID] = []string{mac}
	r.ifaceSeen[d.ID] = s.At
	r.check(r.o.Store.OpenSession(d.ID, s.At))
	r.event(d.ID, s.At, store.EventNew, d.IP)
	if !r.baseline {
		r.pending[d.ID] = s.At.Add(r.o.AlertDelay)
		log.Printf("registry: new device %s %s (%s)", mac, d.IP, d.Vendor)
	}
	r.publish(d)
	if d.Hostname == "" {
		r.queueProbe(d)
	}
}

// applyHostname adopts name when its source ranks at least as high as
// the current one. It reports whether anything changed.
func (r *Registry) applyHostname(d *store.Device, name, src string, at time.Time) bool {
	if name == "" || name == d.Hostname && src == d.HostnameSource {
		return false
	}
	if d.Hostname != "" && passive.HostnamePriority(src) < passive.HostnamePriority(d.HostnameSource) {
		return false
	}
	if name != d.Hostname {
		r.event(d.ID, at, store.EventHostname, name+" ("+src+")")
	}
	d.Hostname, d.HostnameSource = name, src
	return true
}

func (r *Registry) event(id int64, at time.Time, kind, detail string) {
	r.check(r.o.Store.AddEvent(id, at, kind, detail))
}

func (r *Registry) check(err error) {
	if err != nil {
		log.Printf("registry: store: %v", err)
	}
}

func (r *Registry) queueProbe(d *store.Device) {
	if r.o.Resolve == nil || d.IP == "" || d.Hostname != "" {
		return
	}
	if last, ok := r.lastProbe[d.ID]; ok && r.o.Now().Sub(last) < reprobeAfter {
		return
	}
	r.lastProbe[d.ID] = r.o.Now()
	select {
	case r.probes <- d.ID:
	default:
	}
}

// Run drives the periodic work — flushing, offline detection, probes,
// alerts and pruning — until ctx is cancelled.
func (r *Registry) Run(ctx context.Context) {
	for i := 0; i < 2; i++ {
		go r.probeWorker(ctx)
	}
	r.prune()
	flush := time.NewTicker(flushEvery)
	alerts := time.NewTicker(time.Second)
	prune := time.NewTicker(24 * time.Hour)
	defer flush.Stop()
	defer alerts.Stop()
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			r.Flush()
			return
		case <-flush.C:
			r.Flush()
		case <-alerts.C:
			r.sendDueAlerts(ctx)
		case <-prune.C:
			r.prune()
		}
	}
}

// Flush writes pending last-seen times and marks silent devices offline.
func (r *Registry) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.o.Now()
	touched := map[int64]time.Time{}
	for id := range r.dirty {
		if d, ok := r.devices[id]; ok {
			touched[id] = d.LastSeen
		}
	}
	r.dirty = map[int64]bool{}
	if len(touched) > 0 {
		r.check(r.o.Store.TouchDevices(touched))
	}
	for _, d := range r.devices {
		if d.Online && now.Sub(d.LastSeen) > r.o.OfflineAfter {
			d.Online = false
			r.check(r.o.Store.UpdateDevice(d))
			r.check(r.o.Store.CloseSession(d.ID, d.LastSeen))
			r.event(d.ID, d.LastSeen, store.EventOffline, "")
			r.publish(d)
			delete(touched, d.ID)
		}
	}
	for id := range touched {
		r.publish(r.devices[id])
	}
}

func (r *Registry) prune() {
	n, err := r.o.Store.Prune(r.o.Now().Add(-r.o.Retention))
	if err != nil {
		log.Printf("registry: prune: %v", err)
	} else if n > 0 {
		log.Printf("registry: pruned %d history rows older than %s", n, r.o.Retention)
	}
}

func (r *Registry) probeWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-r.probes:
			r.mu.Lock()
			d, ok := r.devices[id]
			var ip net.IP
			if ok && d.Hostname == "" {
				ip = net.ParseIP(d.IP)
			}
			r.mu.Unlock()
			if ip == nil {
				continue
			}
			name, src := r.o.Resolve(ctx, ip)
			if name == "" {
				continue
			}
			r.mu.Lock()
			if d, ok := r.devices[id]; ok && r.applyHostname(d, name, src, r.o.Now()) {
				r.check(r.o.Store.UpdateDevice(d))
				r.publish(d)
			}
			r.mu.Unlock()
		}
	}
}

// sendDueAlerts batches every new-device alert whose delay has passed
// into one message.
func (r *Registry) sendDueAlerts(ctx context.Context) {
	r.mu.Lock()
	now := r.o.Now()
	var due []notify.DeviceInfo
	for id, at := range r.pending {
		if now.Before(at) {
			continue
		}
		delete(r.pending, id)
		d, ok := r.devices[id]
		if !ok || d.Known { // merged, deleted or already acknowledged
			continue
		}
		due = append(due, r.info(d))
	}
	r.mu.Unlock()
	if len(due) == 0 {
		return
	}
	set := r.o.Settings.Get()
	if !set.NotifyNew || !set.Configured() {
		return
	}
	sort.Slice(due, func(i, j int) bool { return due[i].FirstSeen.Before(due[j].FirstSeen) })
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		err := r.o.Send(ctx, set, notify.Message{Event: notify.EventNewDevice, Devices: due})
		r.mu.Lock()
		if err != nil {
			log.Printf("alerts: %v", err)
			r.alertState.LastError = err.Error()
		} else {
			r.alertState.LastSent, r.alertState.LastError = r.o.Now(), ""
		}
		st := r.alertState
		r.mu.Unlock()
		r.o.Hub.Publish("alerts", st)
	}()
}

// AlertStatus returns the outcome of the last alert delivery.
func (r *Registry) AlertStatus() AlertStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.alertState
}

func (r *Registry) info(d *store.Device) notify.DeviceInfo {
	v := r.view(d)
	info := notify.DeviceInfo{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, Vendor: d.Vendor, Model: d.Model,
		IP: d.IP, MAC: d.MAC, Interface: d.Iface, FirstSeen: d.FirstSeen, Randomized: v.Randomized,
	}
	if o, ok := r.devices[v.SameNameAs]; ok {
		info.SameNameAs = firstNonEmpty(o.Name, o.Hostname)
	}
	return info
}

// view builds the API representation. Caller holds r.mu.
func (r *Registry) view(d *store.Device) View {
	v := View{Device: *d, MACs: append([]string(nil), r.macs[d.ID]...), Randomized: randomized(d.MAC)}
	if d.Hostname != "" {
		var best *store.Device
		for _, o := range r.devices {
			if o.ID == d.ID || !strings.EqualFold(o.Hostname, d.Hostname) || !o.FirstSeen.Before(d.FirstSeen) {
				continue
			}
			if best == nil || o.FirstSeen.Before(best.FirstSeen) {
				best = o
			}
		}
		if best != nil {
			v.SameNameAs = best.ID
		}
	}
	return v
}

func (r *Registry) publish(d *store.Device) { r.o.Hub.Publish("device", r.view(d)) }

// randomized reports a locally administered MAC — what phones use for
// per-network MAC randomization.
func randomized(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0
}

// Devices returns every device, online first, then by IP.
func (r *Registry) Devices() []View {
	r.mu.Lock()
	out := make([]View, 0, len(r.devices))
	for _, d := range r.devices {
		out = append(out, r.view(d))
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return ipKey(out[i].IP) < ipKey(out[j].IP)
	})
	return out
}

func ipKey(s string) string {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return "\xff" + s
	}
	return string(ip)
}

// Device returns one device.
func (r *Registry) Device(id int64) (View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return View{}, ErrNotFound
	}
	return r.view(d), nil
}

// Update applies a user edit.
func (r *Registry) Update(id int64, p Patch) (View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return View{}, ErrNotFound
	}
	if p.Name != nil {
		d.Name = limit(strings.TrimSpace(*p.Name), 64)
	}
	if p.Note != nil {
		d.Note = limit(strings.TrimSpace(*p.Note), 500)
	}
	if p.Known != nil {
		d.Known = *p.Known
		if d.Known {
			delete(r.pending, id)
		}
	}
	if err := r.o.Store.UpdateDevice(d); err != nil {
		return View{}, err
	}
	r.publish(d)
	return r.view(d), nil
}

func limit(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// MarkAllKnown acknowledges every device.
func (r *Registry) MarkAllKnown() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.o.Store.MarkAllKnown(); err != nil {
		return err
	}
	r.pending = map[int64]time.Time{}
	for _, d := range r.devices {
		if !d.Known {
			d.Known = true
			r.publish(d)
		}
	}
	return nil
}

// Merge folds device src into dst: its MACs, history and, where dst has
// none, its name and note. Use it when a phone's randomized MAC shows up
// as a new device.
func (r *Registry) Merge(src, dst int64) (View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok1 := r.devices[src]
	d, ok2 := r.devices[dst]
	if !ok1 || !ok2 || src == dst {
		return View{}, ErrNotFound
	}
	m := *d
	if m.Name == "" {
		m.Name = s.Name
	}
	if m.Note == "" {
		m.Note = s.Note
	}
	m.Known = d.Known || s.Known
	if s.FirstSeen.Before(m.FirstSeen) {
		m.FirstSeen = s.FirstSeen
	}
	if s.LastSeen.After(d.LastSeen) {
		m.LastSeen, m.MAC, m.Vendor, m.IP, m.Iface = s.LastSeen, s.MAC, s.Vendor, s.IP, s.Iface
	}
	m.Online = d.Online || s.Online
	if s.Hostname != "" && (m.Hostname == "" || passive.HostnamePriority(s.HostnameSource) > passive.HostnamePriority(m.HostnameSource)) {
		m.Hostname, m.HostnameSource = s.Hostname, s.HostnameSource
	}
	if m.Model == "" {
		m.Model = s.Model
	}
	if err := r.o.Store.Merge(src, &m); err != nil {
		return View{}, err
	}
	*d = m
	for _, mac := range r.macs[src] {
		r.byMAC[mac] = dst
	}
	r.macs[dst] = append(r.macs[dst], r.macs[src]...)
	delete(r.macs, src)
	delete(r.devices, src)
	delete(r.pending, src)
	delete(r.dirty, src)
	r.event(dst, r.o.Now(), store.EventMerged, strings.Join(r.macs[dst], ", "))
	r.o.Hub.Publish("remove", map[string]int64{"id": src})
	r.publish(d)
	// Other devices' merge hints may point at src.
	for _, o := range r.devices {
		if o.ID != dst && strings.EqualFold(o.Hostname, d.Hostname) && o.Hostname != "" {
			r.publish(o)
		}
	}
	return r.view(d), nil
}

// Delete forgets a device and its history. If it shows up again it is
// treated as new.
func (r *Registry) Delete(id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.devices[id]; !ok {
		return ErrNotFound
	}
	if err := r.o.Store.DeleteDevice(id); err != nil {
		return err
	}
	for _, mac := range r.macs[id] {
		delete(r.byMAC, mac)
	}
	for _, m := range []map[int64]time.Time{r.ifaceSeen, r.lastProbe, r.pending} {
		delete(m, id)
	}
	delete(r.macs, id)
	delete(r.devices, id)
	delete(r.dirty, id)
	r.o.Hub.Publish("remove", map[string]int64{"id": id})
	return nil
}

// History is a device's recent presence and events.
type History struct {
	Sessions []store.Session `json:"sessions"`
	Events   []store.Event   `json:"events"`
}

// History returns sessions since `since` and the latest events.
func (r *Registry) History(id int64, since time.Time) (History, error) {
	r.mu.Lock()
	_, ok := r.devices[id]
	r.mu.Unlock()
	if !ok {
		return History{}, ErrNotFound
	}
	var h History
	var err error
	if h.Sessions, err = r.o.Store.Sessions(id, since); err != nil {
		return h, err
	}
	h.Events, err = r.o.Store.Events(id, 100)
	return h, err
}

// SendTest sends a test message with the given settings.
func (r *Registry) SendTest(ctx context.Context, s notify.Settings) error {
	return r.o.Send(ctx, s, notify.Message{Event: notify.EventTest})
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
