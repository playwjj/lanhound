package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/logx"
	"github.com/playwjj/lanhound/internal/router"
	"github.com/playwjj/lanhound/internal/secret"
	"github.com/playwjj/lanhound/internal/store"
)

const (
	routersKey  = "routers"
	routerEvery = 2 * time.Minute
)

// RouterStatus is one source's configuration (password masked) and how
// its last poll went.
type RouterStatus struct {
	router.Config
	LastPoll  time.Time `json:"lastPoll"`
	LastError string    `json:"lastError,omitempty"`
	Devices   int       `json:"devices"`
}

// Routers polls the configured router/modem sources.
type Routers struct {
	store    *store.Store
	registry *Registry
	hub      *Hub
	newSrc   func(router.Config) (router.Source, error)

	failures logx.Failures

	mu      sync.Mutex
	configs []router.Config
	sources map[string]router.Source
	status  map[string]*RouterStatus
	kick    chan struct{}
}

// NewRouters loads the stored sources.
func NewRouters(st *store.Store, reg *Registry, hub *Hub) (*Routers, error) {
	r := &Routers{store: st, registry: reg, hub: hub, newSrc: router.New, sources: map[string]router.Source{}, status: map[string]*RouterStatus{}, kick: make(chan struct{}, 1)}
	if _, err := st.GetJSON(routersKey, &r.configs); err != nil {
		return nil, err
	}
	return r, nil
}

// Run polls every source every two minutes until ctx is done.
func (r *Routers) Run(ctx context.Context) {
	t := time.NewTicker(routerEvery)
	defer t.Stop()
	for {
		r.pollAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.kick:
		}
	}
}

func (r *Routers) pollAll(ctx context.Context) {
	r.mu.Lock()
	cfgs := append([]router.Config(nil), r.configs...)
	r.mu.Unlock()
	for _, c := range cfgs {
		if c.Enabled {
			r.poll(ctx, c)
		}
	}
	r.hub.Publish("routers", r.Status())
}

func (r *Routers) poll(ctx context.Context, c router.Config) {
	r.mu.Lock()
	src, ok := r.sources[c.ID]
	if !ok {
		var err error
		if src, err = r.newSrc(c); err != nil {
			r.setStatus(c.ID, func(s *RouterStatus) { s.LastPoll, s.LastError = time.Now(), err.Error() })
			r.mu.Unlock()
			return
		}
		r.sources[c.ID] = src
	}
	r.mu.Unlock()

	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	entries, err := src.Fetch(fctx)
	cancel()
	if err != nil {
		r.failures.Fail(lgRouter(), c.ID, "cannot read router", err, "router", c.Label)
		r.mu.Lock()
		r.setStatus(c.ID, func(s *RouterStatus) { s.LastPoll, s.LastError = time.Now(), err.Error() })
		r.mu.Unlock()
		return
	}
	// The first successful sync of a source is a silent baseline, like
	// LanHound's own first sweep.
	syncedKey := "router.synced." + c.ID
	synced, _ := r.store.Setting(syncedKey)
	r.failures.OK(lgRouter(), c.ID, "router readable again", "router", c.Label)
	lgRouter().Debug("router polled", "router", c.Label, "devices", len(entries))
	r.registry.ObserveRouter(c.Label, entries, synced == "")
	if synced == "" {
		_ = r.store.SetSetting(syncedKey, "1")
		lgRouter().Info("router first sync", "router", c.Label, "devices", len(entries))
	}
	r.mu.Lock()
	r.setStatus(c.ID, func(s *RouterStatus) { s.LastPoll, s.LastError, s.Devices = time.Now(), "", len(entries) })
	r.mu.Unlock()
}

// setStatus updates a source's status. Caller holds r.mu.
func (r *Routers) setStatus(id string, f func(*RouterStatus)) {
	st := r.status[id]
	if st == nil {
		st = &RouterStatus{}
		r.status[id] = st
	}
	f(st)
}

// Status lists the sources with passwords masked.
func (r *Routers) Status() []RouterStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RouterStatus, 0, len(r.configs))
	for _, c := range r.configs {
		st := RouterStatus{Config: c}
		if s := r.status[c.ID]; s != nil {
			st.LastPoll, st.LastError, st.Devices = s.LastPoll, s.LastError, s.Devices
		}
		st.Password = secret.Hide(st.Password)
		out = append(out, st)
	}
	return out
}

// resolve fills a masked password from the stored config with the same ID.
func (r *Routers) resolve(c router.Config) router.Config {
	stored := ""
	for _, old := range r.configs {
		if old.ID == c.ID {
			stored = old.Password
		}
	}
	c.Password = secret.Keep(c.Password, stored)
	return c
}

func validate(c *router.Config) error {
	c.Label = strings.TrimSpace(c.Label)
	c.URL = strings.TrimSpace(c.URL)
	if c.URL == "" {
		return errors.New("URL is required")
	}
	if c.Kind != router.KindOpenWrt && c.Kind != router.KindURL {
		return errors.New("unknown router kind")
	}
	if c.Label == "" {
		host := c.URL
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		host, _, _ = strings.Cut(host, "/")
		c.Label = host
	}
	if len([]rune(c.Label)) > 40 {
		c.Label = string([]rune(c.Label)[:40])
	}
	return nil
}

// Put replaces the source list and polls right away.
func (r *Routers) Put(list []router.Config) ([]RouterStatus, error) {
	r.mu.Lock()
	for i := range list {
		list[i] = r.resolve(list[i])
		if err := validate(&list[i]); err != nil {
			r.mu.Unlock()
			return nil, err
		}
		if list[i].ID == "" {
			b := make([]byte, 6)
			_, _ = rand.Read(b)
			list[i].ID = hex.EncodeToString(b)
		}
	}
	if err := r.store.PutJSON(routersKey, list); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.configs = list
	r.sources = map[string]router.Source{} // rebuilt with the new settings
	keep := map[string]*RouterStatus{}
	for _, c := range list {
		if s, ok := r.status[c.ID]; ok {
			keep[c.ID] = s
		}
	}
	r.status = keep
	r.mu.Unlock()
	select {
	case r.kick <- struct{}{}:
	default:
	}
	return r.Status(), nil
}

// TestResult is what "test connection" reports.
type TestResult struct {
	Devices int          `json:"devices"`
	Sample  []TestSample `json:"sample"`
	Error   string       `json:"error,omitempty"`
}

// TestSample is one entry shown in a test result.
type TestSample struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// Test fetches once from a (possibly unsaved) source without recording
// anything.
func (r *Routers) Test(ctx context.Context, c router.Config) TestResult {
	r.mu.Lock()
	c = r.resolve(c)
	r.mu.Unlock()
	if err := validate(&c); err != nil {
		return TestResult{Error: err.Error()}
	}
	src, err := r.newSrc(c)
	if err != nil {
		return TestResult{Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	entries, err := src.Fetch(ctx)
	if err != nil {
		return TestResult{Error: err.Error()}
	}
	res := TestResult{Devices: len(entries), Sample: []TestSample{}}
	for i, e := range entries {
		if i == 8 {
			break
		}
		s := TestSample{MAC: e.MAC.String(), Hostname: e.Hostname}
		if e.IP != nil {
			s.IP = e.IP.String()
		}
		res.Sample = append(res.Sample, s)
	}
	return res
}

func lgRouter() *slog.Logger { return logx.L("router") }
