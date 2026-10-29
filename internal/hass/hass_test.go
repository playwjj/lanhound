package hass

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/store"
)

type fakePub struct {
	mu   sync.Mutex
	msgs map[string]string // retained view: topic → last payload
	log  []string
}

func (f *fakePub) Publish(topic string, retained bool, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if retained {
		if len(payload) == 0 {
			delete(f.msgs, topic)
		} else {
			f.msgs[topic] = string(payload)
		}
	}
	f.log = append(f.log, topic)
	return nil
}

func setup(t *testing.T) (*Bridge, *core.Registry, *fakePub) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	set, _ := core.NewSettings(st, notify.Settings{})
	hub := core.NewHub()
	reg, err := core.NewRegistry(core.Options{Store: st, Hub: hub, Settings: set})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(st, reg, hub, func() string { return "en" }, "v9", "")
	if err != nil {
		t.Fatal(err)
	}
	return b, reg, &fakePub{msgs: map[string]string{}}
}

func observe(reg *core.Registry, mac, ip, name string) int64 {
	hw, _ := net.ParseMAC(mac)
	reg.Observe(passive.Sighting{Iface: "eth0", MAC: hw, IP: net.ParseIP(ip).To4(), Source: passive.SrcARPReply, Hostname: name, HostnameSource: passive.SrcDHCP})
	for _, v := range reg.Devices() {
		if v.MAC == mac {
			return v.ID
		}
	}
	return 0
}

func TestSyncPublishesKnownDevices(t *testing.T) {
	b, reg, p := setup(t)
	nas := observe(reg, "00:11:32:aa:bb:02", "192.168.2.10", "DiskStation")
	observe(reg, "24:0a:c4:00:00:03", "192.168.2.87", "")
	yes := true
	_, _ = reg.Update(nas, core.Patch{Known: &yes})

	cfg := Config{Enabled: true, URL: "mqtt://broker", Prefix: DefaultPrefix}
	if err := b.sync(p, cfg); err != nil {
		t.Fatal(err)
	}
	id := "1"
	conf := p.msgs["homeassistant/device_tracker/lanhound_"+id+"/config"]
	if conf == "" {
		t.Fatalf("known device not published; topics: %v", p.log)
	}
	var c map[string]any
	_ = json.Unmarshal([]byte(conf), &c)
	dev := c["device"].(map[string]any)
	if c["unique_id"] != "lanhound_1" || c["state_topic"] != "lanhound/device/1/state" || dev["name"] != "DiskStation" || dev["via_device"] != "lanhound" {
		t.Fatalf("discovery payload %s", conf)
	}
	if conns := dev["connections"].([]any); conns[0].([]any)[1] != "00:11:32:aa:bb:02" {
		t.Fatalf("connections %v", conns)
	}
	if p.msgs["lanhound/device/1/state"] != "home" || p.msgs["lanhound/status"] != "online" {
		t.Fatalf("state %q status %q", p.msgs["lanhound/device/1/state"], p.msgs["lanhound/status"])
	}
	if _, ok := p.msgs["homeassistant/device_tracker/lanhound_2/config"]; ok {
		t.Fatal("unreviewed device must not be published by default")
	}
	if !strings.Contains(p.msgs["lanhound/stats"], `"online":2`) || !strings.Contains(p.msgs["lanhound/stats"], `"unreviewed":1`) {
		t.Fatalf("stats %s", p.msgs["lanhound/stats"])
	}
	for _, topic := range []string{"homeassistant/sensor/lanhound_online/config", "homeassistant/event/lanhound_alert/config"} {
		if p.msgs[topic] == "" {
			t.Fatalf("missing %s", topic)
		}
	}

	// "all" publishes the unreviewed one too.
	cfg.All = true
	_ = b.sync(p, cfg)
	if p.msgs["homeassistant/device_tracker/lanhound_2/config"] == "" {
		t.Fatal("all=true should publish every device")
	}
}

func TestDeviceUpdatesAndRetraction(t *testing.T) {
	b, reg, p := setup(t)
	id := observe(reg, "00:11:32:aa:bb:02", "192.168.2.10", "DiskStation")
	yes, no := true, false
	v, _ := reg.Update(id, core.Patch{Known: &yes})
	cfg := Config{Enabled: true, URL: "mqtt://broker", Prefix: "ha"}
	_ = b.device(p, cfg, v)
	n := len(p.log)
	_ = b.device(p, cfg, v) // unchanged: discovery config not resent
	if len(p.log)-n != 2 {
		t.Fatalf("unchanged device republished config: %v", p.log[n:])
	}
	name := "NAS"
	v, _ = reg.Update(id, core.Patch{Name: &name})
	_ = b.device(p, cfg, v)
	if !strings.Contains(p.msgs["ha/device_tracker/lanhound_1/config"], `"name":"NAS"`) {
		t.Fatal("rename not republished")
	}
	v.Online = false
	_ = b.device(p, cfg, v)
	if p.msgs["lanhound/device/1/state"] != "not_home" {
		t.Fatal("offline not published")
	}
	v, _ = reg.Update(id, core.Patch{Known: &no})
	_ = b.device(p, cfg, v)
	if _, ok := p.msgs["ha/device_tracker/lanhound_1/config"]; ok {
		t.Fatal("un-known device should be removed from HA")
	}
}

func TestAlertEvent(t *testing.T) {
	b, _, p := setup(t)
	m := notify.Message{Event: notify.EventRogueDHCP, Interface: "eth0", IP: "192.168.2.123", Devices: []notify.DeviceInfo{{MAC: "60:eb:69:e3:3a:4b", Hostname: "pw"}}}
	data, _ := json.Marshal(m)
	if err := b.alert(p, store.Alert{ID: 7, Kind: m.Event, Data: data}); err != nil {
		t.Fatal(err)
	}
	if p.log[len(p.log)-1] != "lanhound/alert" {
		t.Fatalf("topics %v", p.log)
	}
}

func TestBrokerAddr(t *testing.T) {
	cases := map[string]string{
		"mqtt://192.168.2.5":         "tcp://192.168.2.5:1883",
		"192.168.2.5:1884":           "tcp://192.168.2.5:1884",
		"mqtts://broker.lan":         "ssl://broker.lan:8883",
		"mqtt://user:pw@broker:1883": "tcp://broker:1883",
	}
	for in, want := range cases {
		if got, err := brokerAddr(in); err != nil || got != want {
			t.Errorf("brokerAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := brokerAddr("http://x"); err == nil {
		t.Error("http scheme must be rejected")
	}
	if got := redactURL("mqtt://user:secret@broker:1883"); strings.Contains(got, "secret") {
		t.Errorf("redact: %s", got)
	}
}

func TestConfigPasswordMasked(t *testing.T) {
	b, _, _ := setup(t)
	if _, err := b.Put(Config{Enabled: true, URL: "mqtt://broker", Username: "ha", Password: "test-only"}); err != nil {
		t.Fatal(err)
	}
	c := b.Config()
	if c.Password == "test-only" || c.Prefix != DefaultPrefix {
		t.Fatalf("config %+v", c)
	}
	if _, err := b.Put(c); err != nil {
		t.Fatal(err)
	}
	if b.cfg.Password != "test-only" {
		t.Fatal("masked password overwrote the real one")
	}
}
