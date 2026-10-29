package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/router"
	"github.com/playwjj/lanhound/internal/scanner"
	"github.com/playwjj/lanhound/internal/security"
	"github.com/playwjj/lanhound/internal/services"
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
	if !nu.Randomized || nu.SameAs != old {
		t.Fatalf("new device %+v", nu)
	}
	h.clk.Add(time.Minute)
	got := h.alerts(t)
	if len(got) != 1 || got[0].Devices[0].SameAs != "Mom's phone" {
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
	if !strings.Contains(log[0].Text["zh"].Title, "DiskStation 恢复在线") || log[0].Text["en"].Lines[0] != "Offline for 2h11m" {
		t.Fatalf("alert wording %+v", log[0].Text)
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

func TestActivity(t *testing.T) {
	h := newHarness(t, "")
	h.clk.now = time.Date(2027, 1, 15, 10, 30, 0, 0, time.UTC)
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87")) // online since 10:30
	h.clk.Add(-5 * time.Hour)
	h.r.Observe(sight("24:0a:c4:00:00:04", "192.168.2.88")) // 05:30, never closed below
	h.clk.Add(5 * time.Hour)
	a, err := h.r.Activity(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Hourly) != 24 || !a.Start.Equal(time.Date(2027, 1, 14, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("window %v len %d", a.Start, len(a.Hourly))
	}
	last := a.Hourly[23] // 10:00–11:00
	if last != 2 || a.Hourly[18] != 1 || a.Hourly[17] != 0 {
		t.Fatalf("hourly %v", a.Hourly)
	}
}

func TestIPv6Addresses(t *testing.T) {
	h := newHarness(t, "")
	ll := net.ParseIP("fe80::260a:c4ff:fe00:3")
	h.r.Observe(sight("24:0a:c4:00:00:03", "", func(s *passive.Sighting) { s.Source, s.IP6 = passive.SrcNDP, ll }))
	v := h.r.Devices()[0]
	if v.IP != "" || len(v.IPv6) != 1 || v.IPv6[0] != ll.String() {
		t.Fatalf("IPv6-only device %+v", v)
	}
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	for i := 0; i < 8; i++ {
		ip := net.ParseIP(fmt.Sprintf("240e:3b0::%d", i))
		h.r.Observe(sight("24:0a:c4:00:00:03", "", func(s *passive.Sighting) { s.Source, s.IP6 = passive.SrcNDP, ip }))
	}
	h.r.Observe(sight("24:0a:c4:00:00:03", "", func(s *passive.Sighting) { s.Source, s.IP6 = passive.SrcNDP, net.ParseIP("240e:3b0::7") }))
	v, _ = h.r.Device(v.ID)
	if v.IP != "192.168.2.87" || len(v.IPv6) != maxIPv6 || v.IPv6[0] != "240e:3b0::7" {
		t.Fatalf("ipv6 list %v", v.IPv6)
	}
	h.r.Flush()
	devs, _, _ := h.st.Devices()
	if len(devs[0].IPv6) != maxIPv6 {
		t.Fatalf("ipv6 not persisted: %v", devs[0].IPv6)
	}
}

func fp(name, model, dhcp string) func(*passive.Sighting) {
	return func(s *passive.Sighting) {
		s.Hostname, s.HostnameSource, s.Model, s.DHCPFingerprint = name, passive.SrcDHCP, model, dhcp
	}
}

const iosFP = "1,121,3,6,15,108,114,119,252,95,44,46|"

func TestFingerprintRecognizesKnownPhone(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("5a:1c:9e:44:55:0b", "192.168.2.52", fp("Moms-iPhone", "", iosFP)))
	mom := h.r.Devices()[0].ID
	known := true
	_, _ = h.r.Update(mom, Patch{Known: &known})
	h.r.EndBaseline()

	h.clk.Add(30 * time.Minute) // the old MAC went quiet; a new one appears
	h.r.Observe(sight("2e:0f:7a:61:3b:11", "192.168.2.53", fp("Moms-iPhone", "", iosFP)))
	h.clk.Add(time.Minute)
	h.r.sendDueAlerts(context.Background())
	time.Sleep(50 * time.Millisecond)
	h.mu.Lock()
	sent := len(h.sent)
	h.mu.Unlock()
	if sent != 0 {
		t.Fatal("a recognized phone must not page anyone")
	}
	log, _ := h.r.Alerts(5)
	if len(log) != 1 || log[0].Kind != notify.EventRecognized || log[0].DeviceID == mom {
		t.Fatalf("want a recognized entry in the log, got %+v", log)
	}
	var nu View
	for _, v := range h.r.Devices() {
		if v.ID != mom {
			nu = v
		}
	}
	if nu.SameAs != mom || strings.Join(nu.SameAsWhy, ",") != "dhcp,hostname" {
		t.Fatalf("hint %+v", nu)
	}
}

func TestFingerprintGenericNamesNeedMoreEvidence(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("5a:00:00:00:00:01", "192.168.2.60", fp("iPhone", "", "")))
	h.r.EndBaseline()
	h.clk.Add(time.Hour)
	// Another family member's iPhone: same generic name only.
	h.r.Observe(sight("5a:00:00:00:00:02", "192.168.2.61", fp("iPhone", "", "")))
	for _, v := range h.r.Devices() {
		if v.SameAs != 0 {
			t.Fatalf("generic hostname alone must not suggest a match: %+v", v)
		}
	}
	// Same generic name + same model + same DHCP fingerprint: worth a hint.
	h.clk.Add(time.Hour)
	h.r.Observe(sight("5a:00:00:00:00:03", "192.168.2.62", fp("iPhone", "iPhone15,2", iosFP)))
	h.r.mu.Lock()
	first := h.r.devices[h.r.byMAC["5a:00:00:00:00:01"]]
	first.Model, first.DHCPFP = "iPhone15,2", iosFP
	h.r.mu.Unlock()
	v, _ := h.r.Device(h.r.byMAC["5a:00:00:00:00:03"])
	if v.SameAs != first.ID || v.SameAsWhy[0] != "dhcp" {
		t.Fatalf("want a hint for generic+model+dhcp, got %+v", v)
	}
}

func TestFingerprintSkipsConcurrentDevices(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("5a:00:00:00:00:01", "192.168.2.60", fp("Kids-iPad", "", iosFP)))
	h.clk.Add(time.Hour)
	h.r.Observe(sight("5a:00:00:00:00:02", "192.168.2.61", fp("Kids-iPad", "", iosFP)))
	h.clk.Add(5 * time.Minute)
	h.r.Observe(sight("5a:00:00:00:00:01", "192.168.2.60")) // the first one is still around
	v, _ := h.r.Device(h.r.byMAC["5a:00:00:00:00:02"])
	if v.SameAs != 0 {
		t.Fatalf("two devices online at once are not one device: %+v", v)
	}
}

type fakeProber struct{ calls []string }

func (f *fakeProber) Probe(_ context.Context, ip string) []services.Service {
	f.calls = append(f.calls, ip)
	return []services.Service{{Port: 554, Name: "rtsp"}, {Port: 23, Name: "telnet", Risky: true}}
}

func TestServiceScan(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("00:bc:99:aa:00:09", "192.168.2.40"))
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	ss, err := NewServiceScan(h.st, h.r, nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProber{}
	ss.prober = fp
	if ss.Enabled() {
		t.Fatal("service scanning must be off by default")
	}
	id, ok := h.r.nextForServices()
	if !ok {
		t.Fatal("nothing to probe")
	}
	ss.probe(context.Background(), id)
	v, _ := h.r.Device(id)
	if len(v.Services) != 2 || v.Kind != services.KindCamera || v.ServicesAt.IsZero() {
		t.Fatalf("after probe %+v", v)
	}
	// The other device is next; the probed one waits a day.
	id2, _ := h.r.nextForServices()
	ss.probe(context.Background(), id2)
	if _, ok := h.r.nextForServices(); ok {
		t.Fatal("both probed; nothing should be due")
	}
	h.clk.Add(25 * time.Hour)
	h.r.Observe(sight("00:bc:99:aa:00:09", "192.168.2.40"))
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))
	if _, ok := h.r.nextForServices(); !ok {
		t.Fatal("refresh after a day")
	}
	if err := ss.SetEnabled(true); err != nil || !ss.Enabled() {
		t.Fatal(err)
	}
	ss2, _ := NewServiceScan(h.st, h.r, nil)
	if !ss2.Enabled() {
		t.Fatal("switch not persisted")
	}
	devs, _, _ := h.st.Devices()
	for _, d := range devs {
		if d.ID == id && (len(d.Services) != 2 || !d.Services[1].Risky) {
			t.Fatalf("services not stored: %+v", d.Services)
		}
	}
}

func TestProbes(t *testing.T) {
	h := newHarness(t, "")
	var got []passive.Sighting
	h.r.EndBaseline()
	p, err := NewProbes(h.st, func(s passive.Sighting, quiet bool) {
		got = append(got, s)
		if quiet {
			h.r.ObserveQuiet(s)
		} else {
			h.r.Observe(s)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	p.now = h.clk.Now
	h.r.o.IfaceStale = p.Stale

	ps, token, err := p.Add("guest vlan!")
	if err != nil || ps.Name != "guest-vlan" || !strings.HasPrefix(token, "lhp_") {
		t.Fatalf("add: %+v %q %v", ps, token, err)
	}
	if _, _, err := p.Add("Guest-VLAN"); err == nil {
		t.Fatal("duplicate names must be refused")
	}
	if err := p.Ingest("lhp_wrong", Upload{}); err != ErrBadToken {
		t.Fatalf("wrong token: %v", err)
	}
	up := Upload{
		Version:    "v9",
		Interfaces: []scanner.Status{{Interface: "eth0", Network: "192.168.50.0/24"}},
		Gateways:   map[string][]string{"eth0": {"192.168.50.1"}},
		Sightings:  []WireSighting{{Iface: "eth0", MAC: "24:0a:c4:00:00:50", IP: "192.168.50.20", Source: passive.SrcARPReply, At: h.clk.Now()}},
	}
	if err := p.Ingest(token, up); err != nil {
		t.Fatal(err)
	}
	v := h.r.Devices()[0]
	if v.Iface != "guest-vlan/eth0" || v.IP != "192.168.50.20" || !v.Online {
		t.Fatalf("device %+v", v)
	}
	// Before the probe's first sweep finished: silent baseline.
	h.clk.Add(time.Minute)
	if a := h.alerts(t); len(a) != 0 {
		t.Fatalf("a new probe's first sweep must not alert: %+v", a)
	}
	up.Interfaces[0].LastSweep = h.clk.Now()
	up.Sightings = append(up.Sightings, WireSighting{Iface: "eth0", MAC: "24:0a:c4:00:00:51", IP: "192.168.50.21", Source: passive.SrcARPReply, At: h.clk.Now()})
	_ = p.Ingest(token, up) // still the first sweep's tail
	up.Sightings = []WireSighting{{Iface: "eth0", MAC: "e4:95:6e:40:11:22", IP: "192.168.50.99", Source: passive.SrcDHCP, At: h.clk.Now()}}
	_ = p.Ingest(token, up) // a genuinely new device afterwards
	h.clk.Add(time.Minute)
	if a := h.alerts(t); len(a) != 1 || a[0].Devices[0].MAC != "e4:95:6e:40:11:22" {
		t.Fatalf("want one alert for the later device, got %+v", a)
	}
	st := p.Status()
	if len(st) != 1 || !st[0].Online || st[0].Interfaces[0].Interface != "guest-vlan/eth0" || st[0].Version != "v9" {
		t.Fatalf("status %+v", st)
	}
	if gw := p.Gateways()["guest-vlan/eth0"]; len(gw) != 1 || gw[0].String() != "192.168.50.1" {
		t.Fatalf("gateways %v", gw)
	}

	// The probe goes silent: its devices are not all marked offline.
	h.clk.Add(30 * time.Minute)
	h.r.Flush()
	if v, _ := h.r.Device(v.ID); !v.Online {
		t.Fatal("devices behind a silent probe must not go offline")
	}
	if p.Status()[0].Online || p.Interfaces()[0].Error != "probe offline" {
		t.Fatal("probe should show offline")
	}
	// Removing the probe revokes its token.
	if err := p.Remove(ps.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Ingest(token, up); err != ErrBadToken {
		t.Fatal("removed probe's token must stop working")
	}
	p2, _ := NewProbes(h.st, func(passive.Sighting, bool) {})
	if len(p2.Status()) != 0 {
		t.Fatal("removal not persisted")
	}
}

func TestLink(t *testing.T) {
	h := newHarness(t, "")
	h.r.Observe(sight("da:00:00:00:00:51", "192.168.2.51"))                               // random MAC
	h.r.Observe(sight("24:0a:c4:00:00:03", "192.168.2.87"))                               // Espressif
	h.r.Observe(sight("00:11:32:aa:bb:02", "192.168.2.10"))                               // Synology, no clue yet
	h.r.Observe(sight("f0:18:98:00:00:01", "192.168.2.20", fp("Moms-iPhone", "", iosFP))) // Apple, phone name
	byMAC := func() map[string]View {
		m := map[string]View{}
		for _, v := range h.r.Devices() {
			m[v.MAC] = v
		}
		return m
	}
	m := byMAC()
	if l := m["da:00:00:00:00:51"].Link; l == nil || l.Type != "wifi" || l.Certain || l.Reasons[0] != "random-mac" {
		t.Fatalf("random MAC: %+v", l)
	}
	if l := m["24:0a:c4:00:00:03"].Link; l == nil || l.Reasons[0] != "wifi-chip" {
		t.Fatalf("espressif: %+v", l)
	}
	if l := m["f0:18:98:00:00:01"].Link; l == nil || l.Reasons[0] != "phone" {
		t.Fatalf("iphone: %+v", l)
	}
	if m["00:11:32:aa:bb:02"].Link != nil {
		t.Fatal("no clue should mean no guess")
	}
	h.r.setServices(m["00:11:32:aa:bb:02"].ID, nil, services.KindNAS)
	if l := byMAC()["00:11:32:aa:bb:02"].Link; l == nil || l.Type != "wired" || l.Certain {
		t.Fatalf("NAS guess: %+v", l)
	}

	// A router report makes it certain, and expires.
	hw, _ := net.ParseMAC("24:0a:c4:00:00:03")
	h.r.ObserveRouter("OpenWrt", []router.Entry{{MAC: hw, Wireless: &router.Wireless{Band: "2.4 GHz", Signal: -71}}}, false)
	if l := byMAC()["24:0a:c4:00:00:03"].Link; l == nil || !l.Certain || l.Band != "2.4 GHz" || l.Via != "OpenWrt" {
		t.Fatalf("router report: %+v", l)
	}
	// The router still has Wi-Fi clients but no longer lists this one.
	other, _ := net.ParseMAC("da:00:00:00:00:51")
	h.r.ObserveRouter("OpenWrt", []router.Entry{{MAC: hw}, {MAC: other, Wireless: &router.Wireless{Band: "5 GHz"}}}, false)
	if l := byMAC()["24:0a:c4:00:00:03"].Link; l == nil || l.Certain {
		t.Fatalf("report should be withdrawn: %+v", l)
	}
	h.clk.Add(wifiStale + time.Minute)
	if l := byMAC()["da:00:00:00:00:51"].Link; l == nil || l.Certain {
		t.Fatalf("stale report should fall back to a guess: %+v", l)
	}
}
