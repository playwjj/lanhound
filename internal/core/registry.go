package core

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/logx"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/oui"
	"github.com/playwjj/lanhound/internal/store"
)

// ErrNotFound is returned for unknown device IDs.
var ErrNotFound = errors.New("device not found")

// ErrInvalid is returned for an edit with a value out of range.
var ErrInvalid = errors.New("invalid value")

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
	// IfaceStale, when set, reports interfaces whose watcher (a remote
	// probe) stopped reporting; their devices keep their state instead of
	// all going offline at once.
	IfaceStale func(iface string) bool
}

// View is a device as the API presents it.
type View struct {
	store.Device
	MACs       []string `json:"macs"`
	Randomized bool     `json:"randomized"`
	// SameAs points at an older device this one most likely is, under a
	// new randomized MAC; SameAsWhy lists the evidence (hostname, model,
	// dhcp). The UI offers a one-click merge.
	SameAs    int64    `json:"sameAs,omitempty"`
	SameAsWhy []string `json:"sameAsWhy,omitempty"`
	// Link is Wi-Fi or wired: certain when a router reported it,
	// otherwise a guess with reasons; nil when there is no clue.
	Link *Link `json:"link,omitempty"`
}

// Patch is a user edit; nil fields are left alone.
type Patch struct {
	Name     *string `json:"name"`
	Note     *string `json:"note"`
	Known    *bool   `json:"known"`
	Critical *bool   `json:"critical"`
	LinkType *string `json:"linkType"` // "wifi", "wired" or "" (automatic)
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
	ctx        context.Context // set by Run; used by background alert delivery

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

// SetIfaceStale installs Options.IfaceStale after construction (the
// probe manager needs the registry first).
func (r *Registry) SetIfaceStale(f func(string) bool) {
	r.mu.Lock()
	r.o.IfaceStale = f
	r.mu.Unlock()
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
		lg().Info("baseline complete; alerting on new devices from now on", "devices", n)
		r.o.Hub.Publish("baseline", false)
	}
}

// RouterIfacePrefix marks devices known only from a router's table.
const RouterIfacePrefix = "router:"

// maxIPv6 bounds the addresses kept per device: privacy extensions
// rotate global addresses daily.
const maxIPv6 = 6

// Run drives the periodic work — flushing, offline detection, probes,
// alerts and pruning — until ctx is cancelled.
func (r *Registry) Run(ctx context.Context) {
	r.mu.Lock()
	r.ctx = ctx
	r.mu.Unlock()
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
		if d.Online && now.Sub(d.LastSeen) > r.o.OfflineAfter && (r.o.IfaceStale == nil || !r.o.IfaceStale(d.Iface)) {
			d.Online = false
			r.check(r.o.Store.UpdateDevice(d))
			r.check(r.o.Store.CloseSession(d.ID, d.LastSeen))
			r.event(d.ID, d.LastSeen, store.EventOffline, "")
			if d.Critical {
				r.criticalAlert(d, false, 0)
			}
			r.publish(d)
			delete(touched, d.ID)
		}
	}
	// Only last-seen changed for these: one small message for all of
	// them instead of a full device view each.
	if len(touched) > 0 {
		seen := make(map[int64]time.Time, len(touched))
		for id, at := range touched {
			seen[id] = at
		}
		r.o.Hub.Publish("seen", seen)
	}
}

func (r *Registry) prune() {
	n, err := r.o.Store.Prune(r.o.Now().Add(-r.o.Retention))
	if err != nil {
		lg().Error("cannot prune history", "err", err)
	} else if n > 0 {
		lg().Info("pruned old history", "rows", n, "older_than", r.o.Retention.String())
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
			lg().Debug("name probe", "ip", ip.String(), "name", name, "source", src)
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
		// One of ours under a new random MAC: log it, don't page anyone.
		if m, ok := r.bestMatch(d, nil); ok && m.Score >= RecognizeScore && r.devices[m.ID].Known {
			info := r.info(d)
			r.raise(notify.Message{Event: notify.EventRecognized, Interface: d.Iface, Devices: []notify.DeviceInfo{info, r.info(r.devices[m.ID])}}, d.ID)
			continue
		}
		due = append(due, r.info(d))
	}
	r.mu.Unlock()
	if len(due) == 0 {
		return
	}
	sort.Slice(due, func(i, j int) bool { return due[i].FirstSeen.Before(due[j].FirstSeen) })
	var id int64
	if len(due) == 1 {
		id = due[0].ID
	}
	r.raise(notify.Message{Event: notify.EventNewDevice, Devices: due}, id)
}

// AlertStatus returns the outcome of the last alert delivery.
func (r *Registry) AlertStatus() AlertStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.alertState
}

// History is a device's recent presence and events.
type History struct {
	Sessions []store.Session `json:"sessions"`
	Events   []store.Event   `json:"events"`
}

func lg() *slog.Logger { return logx.L("registry") }
