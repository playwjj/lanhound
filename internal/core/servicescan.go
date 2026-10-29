package core

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/services"
	"github.com/playwjj/lanhound/internal/store"
)

const (
	servicesKey     = "services.enabled"
	servicesRefresh = 24 * time.Hour
	servicesTick    = 20 * time.Second
)

// ServiceScan probes devices' services in the background when enabled.
// One device per tick, each at most once a day; new devices first.
type ServiceScan struct {
	registry *Registry
	store    *store.Store
	prober   interface {
		Probe(ctx context.Context, ip string) []services.Service
	}
	gateway func(ip string) bool

	mu      sync.Mutex
	enabled bool
	busy    bool
	now     chan int64 // probe this device right away
}

// NewServiceScan loads the on/off switch. gateway reports whether an IP
// is a default gateway (a classification hint); it may be nil.
func NewServiceScan(st *store.Store, reg *Registry, gateway func(string) bool) (*ServiceScan, error) {
	v, err := st.Setting(servicesKey)
	if err != nil {
		return nil, err
	}
	return &ServiceScan{registry: reg, store: st, prober: services.Prober{}, gateway: gateway, enabled: v == "1", now: make(chan int64, 8)}, nil
}

// Enabled reports the switch.
func (s *ServiceScan) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}

// SetEnabled flips the switch.
func (s *ServiceScan) SetEnabled(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := s.store.SetSetting(servicesKey, v); err != nil {
		return err
	}
	s.mu.Lock()
	s.enabled = on
	s.mu.Unlock()
	return nil
}

// ProbeNow queues one device for probing even when background scanning
// is off — the user asked for it.
func (s *ServiceScan) ProbeNow(id int64) {
	select {
	case s.now <- id:
	default:
	}
}

// Run drives the scan until ctx is done.
func (s *ServiceScan) Run(ctx context.Context) {
	t := time.NewTicker(servicesTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.now:
			s.probe(ctx, id)
		case <-t.C:
			if s.Enabled() {
				if id, ok := s.registry.nextForServices(); ok {
					s.probe(ctx, id)
				}
			}
		}
	}
}

func (s *ServiceScan) probe(ctx context.Context, id int64) {
	v, err := s.registry.Device(id)
	if err != nil || v.IP == "" || isRouterIface(v.Iface) {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	svcs := s.prober.Probe(pctx, v.IP)
	if ctx.Err() != nil {
		return
	}
	kind := services.Classify(svcs, services.Hints{
		Vendor: v.Vendor, Hostname: v.Hostname, Model: v.Model,
		Gateway: s.gateway != nil && s.gateway(v.IP),
	})
	if len(svcs) > 0 {
		log.Printf("services: %s %s: %s (%s)", v.IP, v.MAC, services.Summary(svcs), kind)
	}
	s.registry.setServices(id, svcs, kind)
}

// nextForServices picks the online local device whose services are the
// most out of date (never probed first).
func (r *Registry) nextForServices() (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.o.Now()
	var best *store.Device
	for _, d := range r.devices {
		if !d.Online || d.IP == "" || isRouterIface(d.Iface) || now.Sub(d.ServicesAt) < servicesRefresh {
			continue
		}
		if best == nil || d.ServicesAt.Before(best.ServicesAt) {
			best = d
		}
	}
	if best == nil {
		return 0, false
	}
	return best.ID, true
}

func (r *Registry) setServices(id int64, svcs []services.Service, kind string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return
	}
	if svcs == nil {
		svcs = []services.Service{}
	}
	d.Services, d.ServicesAt = svcs, r.o.Now()
	if kind != "" {
		d.Kind = kind
	}
	r.check(r.o.Store.UpdateDevice(d))
	r.publish(d)
}
