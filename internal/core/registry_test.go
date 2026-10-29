package core

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/router"
	"github.com/playwjj/lanhound/internal/security"
	"github.com/playwjj/lanhound/internal/store"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type harness struct {
	r     *Registry
	st    *store.Store
	clk   *clock
	mu    sync.Mutex
	sent  []notify.Message
	sentC chan struct{}
}

func newHarness(t *testing.T, dbPath string) *harness {
	t.Helper()
	if dbPath == "" {
		dbPath = filepath.Join(t.TempDir(), "t.db")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	set, err := NewSettings(st, notify.Settings{TelegramToken: "x", TelegramChatID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{st: st, clk: &clock{now: time.Unix(1_800_000_000, 0)}, sentC: make(chan struct{}, 10)}
	h.r, err = NewRegistry(Options{
		Store: st, Hub: NewHub(), Settings: set, OfflineAfter: 10 * time.Minute, AlertDelay: 20 * time.Second,
		Now: h.clk.Now,
		Send: func(_ context.Context, _ notify.Settings, m notify.Message) error {
			h.mu.Lock()
			h.sent = append(h.sent, m)
			h.mu.Unlock()
			h.sentC <- struct{}{}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func sight(mac string, ip string, opts ...func(*passive.Sighting)) passive.Sighting {
	hw, _ := net.ParseMAC(mac)
	s := passive.Sighting{MAC: hw, Iface: "eth0", Source: passive.SrcARPReply}
	if ip != "" {
		s.IP = net.ParseIP(ip).To4()
	}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func hostname(name, src string) func(*passive.Sighting) {
	return func(s *passive.Sighting) { s.Hostname, s.HostnameSource = name, src }
}

func (h *harness) alerts(t *testing.T) []notify.Message {
	t.Helper()
	h.r.sendDueAlerts(context.Background())
	select {
	case <-h.sentC:
	case <-time.After(200 * time.Millisecond):
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]notify.Message(nil), h.sent...)
}

func TestBaselineIsQuietThenAlerts(t *testing.T) {
	h := newHarness(t, "")
	if !h.r.Baseline() {
		t.Fatal("empty database should start in baseline mode")
	}
	h.r.Observe(sight("8c:3b:ad:00:00:01", "192.168.2.1"))
	h.clk.Add(time.Minute)
	if got := h.alerts(t); len(got) != 0 {
		t.Fatalf("baseline devices must not alert: %+v", got)
	}

	h.r.EndBaseline()
	h.r.Observe(sight("d4:a6:51:00:00:02", "192.168.2.31"))
	h.clk.Add(5 * time.Second)
	// Hostname arrives during the alert delay and makes it into the message.
	h.r.Observe(sight("d4:a6:51:00:00:02", "", hostname("Galaxy-S24", passive.SrcDHCP)))
	if got := h.alerts(t); len(got) != 0 {
		t.Fatal("alert must wait for AlertDelay")
	}
	h.clk.Add(20 * time.Second)
	got := h.alerts(t)
	if len(got) != 1 || len(got[0].Devices) != 1 || got[0].Devices[0].Hostname != "Galaxy-S24" || got[0].Devices[0].Vendor == "" {
		t.Fatalf("alerts %+v", got)
	}
}

func TestKnownDeviceAlertSuppressed(t *testing.T) {
	h := newHarness(t, "")
	h.r.EndBaseline()
	h.r.Observe(sight("d4:a6:51:00:00:02", "192.168.2.31"))
	known := true
	if _, err := h.r.Update(h.r.Devices()[0].ID, Patch{Known: &known}); err != nil {
		t.Fatal(err)
	}
	h.clk.Add(time.Minute)
	if got := h.alerts(t); len(got) != 0 {
		t.Fatalf("acknowledged device should not alert: %+v", got)
	}
}

func TestOnlineOfflineAndHistory(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	id := h.r.Devices()[0].ID

	h.clk.Add(11 * time.Minute)
	h.r.Flush()
	if v, _ := h.r.Device(id); v.Online {
		t.Fatal("device should be offline after OfflineAfter")
	}
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.88"))
	v, _ := h.r.Device(id)
	if !v.Online || v.IP != "192.168.2.88" {
		t.Fatalf("device %+v", v)
	}
	hist, err := h.r.History(id, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist.Sessions) != 2 || !hist.Sessions[1].End.IsZero() {
		t.Fatalf("sessions %+v", hist.Sessions)
	}
	kinds := map[string]bool{}
	for _, e := range hist.Events {
		kinds[e.Kind] = true
	}
	for _, k := range []string{store.EventNew, store.EventOffline, store.EventOnline, store.EventIP} {
		if !kinds[k] {
			t.Errorf("missing %s event in %+v", k, hist.Events)
		}
	}
}

func TestHostnamePriority(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87", hostname("esp-3", passive.SrcRDNS)))
	h.r.Observe(sight("24:0a:c4:00:00:03", "", hostname("Kitchen-Plug", passive.SrcDHCP)))
	h.r.Observe(sight("24:0a:c4:00:00:03", "", hostname("ignored", passive.SrcNBNS)))
	if v := h.r.Devices()[0]; v.Hostname != "Kitchen-Plug" || v.HostnameSource != passive.SrcDHCP {
		t.Fatalf("got %q (%s)", v.Hostname, v.HostnameSource)
	}
}

func TestSameNameHintAndMerge(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("f0:18:98:00:00:01", "192.168.2.20", hostname("Moms-iPhone", passive.SrcDHCP)))
	old := h.r.Devices()[0].ID
	name := "Mom's phone"
	_, _ = h.r.Update(old, Patch{Name: &name})
	h.r.EndBaseline()

	h.clk.Add(time.Hour)
	h.r.Observe(sight("da:a1:19:00:00:02", "192.168.2.41", hostname("moms-iphone", passive.SrcDHCP)))
	var nu View
	for _, v := range h.r.Devices() {
		if v.ID != old {
			nu = v
		}
	}
	if !nu.Randomized || nu.SameNameAs != old {
		t.Fatalf("new device %+v", nu)
	}
	h.clk.Add(time.Minute)
	got := h.alerts(t)
	if len(got) != 1 || got[0].Devices[0].SameNameAs != "Mom's phone" {
		t.Fatalf("alert should carry the same-name hint: %+v", got)
	}

	merged, err := h.r.Merge(nu.ID, old)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.MACs) != 2 || merged.IP != "192.168.2.41" || merged.Name != "Mom's phone" || len(h.r.Devices()) != 1 {
		t.Fatalf("merged %+v", merged)
	}
	// The randomized MAC now resolves to the merged device.
	h.r.Observe(sight("da:a1:19:00:00:02", "192.168.2.42"))
	if v, _ := h.r.Device(old); v.IP != "192.168.2.42" || len(h.r.Devices()) != 1 {
		t.Fatalf("after merge %+v", v)
	}
}

func TestReloadKeepsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	h := newHarness(t, path)
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	h.r.Flush()
	h.st.Close()

	h2 := newHarness(t, path)
	if h2.r.Baseline() {
		t.Fatal("non-empty database must not re-enter baseline mode")
	}
	if len(h2.r.Devices()) != 1 {
		t.Fatal("device not reloaded")
	}
}

func TestDelete(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	id := h.r.Devices()[0].ID
	if err := h.r.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.r.Device(id); err != ErrNotFound {
		t.Fatal("device should be gone")
	}
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	if len(h.r.Devices()) != 1 || h.r.Devices()[0].ID == id {
		t.Fatal("forgotten device should come back as new")
	}
}

func TestSettingsMaskAndEnvLock(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "s.db"))
	defer st.Close()
	s, _ := NewSettings(st, notify.Settings{WebhookURL: "http://env/hook"})
	if _, err := s.Put(notify.Settings{TelegramToken: "123456:ABCDEFGHIJ", TelegramChatID: "9", WebhookURL: "http://ui/hook", NotifyNew: true}); err != nil {
		t.Fatal(err)
	}
	p := s.Public()
	if p.TelegramToken != mask+"GHIJ" || p.WebhookURL != "http://env/hook" || len(p.Locked) != 1 || p.Locked[0] != "webhookUrl" {
		t.Fatalf("public %+v", p)
	}
	// Saving the masked value back keeps the real token.
	if _, err := s.Put(p.Settings); err != nil {
		t.Fatal(err)
	}
	if s.Get().TelegramToken != "123456:ABCDEFGHIJ" {
		t.Fatalf("token lost: %q", s.Get().TelegramToken)
	}
	s2, _ := NewSettings(st, notify.Settings{})
	if s2.Get().TelegramChatID != "9" {
		t.Fatal("settings not persisted")
	}
}

func (h *harness) waitSent(t *testing.T, n int) []notify.Message {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		h.mu.Lock()
		got := append([]notify.Message(nil), h.sent...)
		h.mu.Unlock()
		if len(got) >= n {
			return got
		}
		select {
		case <-h.sentC:
		case <-deadline:
			t.Fatalf("want %d alerts, got %d: %+v", n, len(got), got)
		}
	}
}

func TestCriticalDeviceAlerts(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("00:11:32:aa:bb:02", "192.168.2.10", hostname("DiskStation", passive.SrcMDNS)))
	id := h.r.Devices()[0].ID
	crit := true
	if v, err := h.r.Update(id, Patch{Critical: &crit}); err != nil || !v.Critical {
		t.Fatal("critical flag not set", err)
	}
	h.clk.Add(11 * time.Minute)
	h.r.Flush()
	got := h.waitSent(t, 1)
	if got[0].Event != notify.EventDeviceOffline || got[0].Devices[0].Hostname != "DiskStation" {
		t.Fatalf("offline alert %+v", got[0])
	}
	h.clk.Add(2 * time.Hour)
	h.r.Observe(sight("00:11:32:aa:bb:02", "192.168.2.10"))
	got = h.waitSent(t, 2)
	if got[1].Event != notify.EventDeviceOnline || got[1].Seconds < 2*3600 {
		t.Fatalf("online alert %+v", got[1])
	}
	log, _ := h.r.Alerts(10)
	if len(log) != 2 || log[0].Kind != notify.EventDeviceOnline || log[0].DeviceID != id {
		t.Fatalf("alert log %+v", log)
	}
}

func TestRaiseFindingNamesDevices(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("34:f7:16:57:4b:12", "192.168.2.1"))
	name := "Router"
	_, _ = h.r.Update(h.r.Devices()[0].ID, Patch{Name: &name})
	evil, _ := net.ParseMAC("02:00:00:00:00:66")
	gw, _ := net.ParseMAC("34:f7:16:57:4b:12")
	h.r.RaiseFinding(security.Finding{Event: notify.EventARPConflict, Interface: "eth0", IP: net.IPv4(192, 168, 2, 1), Gateway: true, MACs: []net.HardwareAddr{gw, evil}})
	got := h.waitSent(t, 1)[0]
	if got.IP != "192.168.2.1" || got.Devices[0].Name != "Router" || got.Devices[1].ID != 0 || !got.Devices[1].Randomized || got.Devices[1].IP != "192.168.2.1" {
		t.Fatalf("finding message %+v", got)
	}
	a, m, err := h.r.Alert(1)
	if err != nil || a.Kind != notify.EventARPConflict || !m.Gateway || a.DeviceID == 0 {
		t.Fatalf("logged alert %+v %+v %v", a, m, err)
	}
}

func TestDeliveryRetries(t *testing.T) {
	saved := retryDelays
	retryDelays = []time.Duration{0, 10 * time.Millisecond, 10 * time.Millisecond}
	defer func() { retryDelays = saved }()

	h := newHarness(t, "")
	calls := 0
	h.r.o.Send = func(context.Context, notify.Settings, notify.Message) error {
		h.mu.Lock()
		calls++
		n := calls
		h.mu.Unlock()
		if n < 3 {
			return errors.New("dial tcp: lookup api.telegram.org: i/o timeout")
		}
		h.sentC <- struct{}{}
		return nil
	}
	h.r.raise(notify.Message{Event: notify.EventRogueDHCP}, 0)
	select {
	case <-h.sentC:
	case <-time.After(2 * time.Second):
		t.Fatal("never delivered")
	}
	time.Sleep(20 * time.Millisecond)
	if st := h.r.AlertStatus(); st.LastError != "" || st.LastSent.IsZero() {
		t.Fatalf("status after successful retry %+v", st)
	}
}

type fakeSource struct{ entries []router.Entry }

func (f *fakeSource) Fetch(context.Context) ([]router.Entry, error) { return f.entries, nil }

func entry(mac, ip, name string) router.Entry {
	hw, _ := net.ParseMAC(mac)
	return router.Entry{MAC: hw, IP: net.ParseIP(ip).To4(), Hostname: name}
}

func TestRouterEntries(t *testing.T) {
	h := newHarness(t, "")
	// A local device, seen by ARP, without a name.
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	h.r.EndBaseline()

	src := &fakeSource{entries: []router.Entry{
		entry("24:0a:c4:00:00:03", "192.168.2.87", "Kitchen-Plug"), // local: gets a name
		entry("00:1e:a0:11:22:33", "192.168.1.50", "IPTV-Box"),     // only the router knows it
	}}
	rt, err := NewRouters(h.st, h.r, NewHub())
	if err != nil {
		t.Fatal(err)
	}
	rt.newSrc = func(router.Config) (router.Source, error) { return src, nil }
	if _, err := rt.Put([]router.Config{{Kind: router.KindOpenWrt, URL: "http://192.168.1.1", Password: "test-only", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	cfg := rt.Status()[0]
	if cfg.Label != "192.168.1.1" || cfg.Password != mask || cfg.ID == "" {
		t.Fatalf("config %+v", cfg)
	}
	rt.pollAll(context.Background())

	byMAC := map[string]View{}
	for _, v := range h.r.Devices() {
		byMAC[v.MAC] = v
	}
	plug, box := byMAC["24:0a:c4:00:00:03"], byMAC["00:1e:a0:11:22:33"]
	if plug.Hostname != "Kitchen-Plug" || plug.HostnameSource != passive.SrcRouter || plug.Iface != "eth0" {
		t.Fatalf("local device %+v", plug)
	}
	if box.Iface != "router:192.168.1.1" || !box.Online || box.Hostname != "IPTV-Box" {
		t.Fatalf("router-only device %+v", box)
	}
	h.clk.Add(time.Minute)
	if got := h.alerts(t); len(got) != 0 {
		t.Fatalf("first router sync must be silent: %+v", got)
	}

	// A local device that went quiet stays offline even though the
	// router's table still lists it.
	h.clk.Add(11 * time.Minute)
	h.r.Flush()
	rt.pollAll(context.Background())
	if v, _ := h.r.Device(plug.ID); v.Online {
		t.Fatal("router table must not keep a local device online")
	}
	if v, _ := h.r.Device(box.ID); !v.Online {
		t.Fatal("router-only device should stay online while the router lists it")
	}

	// Later syncs alert on genuinely new devices.
	src.entries = append(src.entries, entry("e4:95:6e:40:11:22", "192.168.1.77", "stranger"))
	rt.pollAll(context.Background())
	h.clk.Add(time.Minute)
	if got := h.alerts(t); len(got) != 1 || got[0].Devices[0].Hostname != "stranger" {
		t.Fatalf("want one new-device alert, got %+v", got)
	}

	// Once the box shows up on our own wire, it moves to our interface.
	h.r.Observe(sight("00:1e:a0:11:22:33", "192.168.2.150"))
	if v, _ := h.r.Device(box.ID); v.Iface != "eth0" {
		t.Fatalf("iface %q", v.Iface)
	}

	// The masked password round-trips without being lost.
	st := rt.Status()
	if _, err := rt.Put([]router.Config{st[0].Config}); err != nil {
		t.Fatal(err)
	}
	if rt.configs[0].Password != "test-only" {
		t.Fatalf("password lost: %q", rt.configs[0].Password)
	}
}
