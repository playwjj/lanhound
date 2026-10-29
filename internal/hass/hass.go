// Package hass publishes LanHound's devices to Home Assistant over MQTT,
// using HA's MQTT discovery: every device becomes a device_tracker
// (home / not_home), plus sensors for the online and unreviewed counts
// and an event entity that fires on every LanHound alert — so "a
// stranger joined" or "the NAS went offline" can drive automations.
//
// Entities are keyed by LanHound's device ID, not the MAC: when a
// phone's randomized MAC is merged into its device, the HA entity stays
// the same.
package hass

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/logx"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/store"
)

// Config is the MQTT/HA setup, edited in the web UI.
type Config struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"` // mqtt://host:1883 or mqtts://host:8883
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Prefix   string `json:"prefix"` // HA discovery prefix
	All      bool   `json:"all"`    // publish every device, not only known ones
	Insecure bool   `json:"insecure,omitempty"`
}

// DefaultPrefix is Home Assistant's default discovery prefix.
const DefaultPrefix = "homeassistant"

const (
	settingsKey = "homeassistant"
	base        = "lanhound" // state topics live under lanhound/…
	statusTopic = base + "/status"
)

// Status reports the bridge to the UI.
type Status struct {
	Enabled   bool   `json:"enabled"`
	Connected bool   `json:"connected"`
	LastError string `json:"lastError,omitempty"`
	Devices   int    `json:"devices"` // device_trackers published
	Locked    bool   `json:"locked"`  // configured by LANHOUND_MQTT_URL
}

// Store persists the config.
type Store interface {
	Setting(key string) (string, error)
	SetSetting(key, value string) error
}

// publisher is the slice of an MQTT client the bridge needs.
type publisher interface {
	Publish(topic string, retained bool, payload []byte) error
}

// Bridge mirrors the registry into Home Assistant.
type Bridge struct {
	store    Store
	registry *core.Registry
	hub      *core.Hub
	language func() string
	version  string
	envURL   string // LANHOUND_MQTT_URL, wins over the UI

	failures logx.Failures

	mu        sync.Mutex
	cfg       Config
	status    Status
	published map[int64]string // device ID → last discovery payload
	reload    chan struct{}
}

// New loads the stored config. envURL (mqtt://user:pass@host:port)
// overrides it when set.
func New(st Store, reg *core.Registry, hub *core.Hub, language func() string, version, envURL string) (*Bridge, error) {
	b := &Bridge{store: st, registry: reg, hub: hub, language: language, version: version, envURL: envURL,
		published: map[int64]string{}, reload: make(chan struct{}, 1)}
	raw, err := st.Setting(settingsKey)
	if err != nil {
		return nil, err
	}
	b.cfg.Prefix = DefaultPrefix
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &b.cfg); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// effective applies the environment override. Caller holds b.mu.
func (b *Bridge) effective() Config {
	c := b.cfg
	if b.envURL != "" {
		c.Enabled, c.URL = true, b.envURL
		c.Username, c.Password = "", ""
	}
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	return c
}

// Config returns the config for display, password masked.
func (b *Bridge) Config() Config {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.effective()
	if c.Password != "" {
		c.Password = "••••••"
	}
	if b.envURL != "" {
		c.URL = redactURL(c.URL)
	}
	return c
}

// Status returns the bridge status.
func (b *Bridge) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.status
	s.Enabled, s.Locked = b.effective().Enabled, b.envURL != ""
	return s
}

// Put stores a new config and reconnects. A masked password means
// "unchanged".
func (b *Bridge) Put(c Config) (Config, error) {
	c.URL = strings.TrimSpace(c.URL)
	c.Prefix = strings.Trim(strings.TrimSpace(c.Prefix), "/")
	if c.Enabled {
		if _, err := brokerAddr(c.URL); err != nil {
			return Config{}, err
		}
	}
	b.mu.Lock()
	if strings.HasPrefix(c.Password, "••") {
		c.Password = b.cfg.Password
	}
	raw, _ := json.Marshal(c)
	if err := b.store.SetSetting(settingsKey, string(raw)); err != nil {
		b.mu.Unlock()
		return Config{}, err
	}
	b.cfg = c
	b.mu.Unlock()
	select {
	case b.reload <- struct{}{}:
	default:
	}
	return b.Config(), nil
}

// Test connects once with c (password may be masked) and disconnects.
func (b *Bridge) Test(c Config) error {
	b.mu.Lock()
	if strings.HasPrefix(c.Password, "••") {
		c.Password = b.cfg.Password
	}
	if b.envURL != "" {
		c = b.effective()
	}
	b.mu.Unlock()
	cl, err := connect(c, "lanhound-test-"+strconv.FormatInt(time.Now().UnixNano()%1e6, 10), false)
	if err != nil {
		return err
	}
	cl.Disconnect(100)
	return nil
}

// brokerAddr turns mqtt://host[:port] / mqtts://… into a paho broker URL.
func brokerAddr(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("MQTT URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "mqtt://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("bad MQTT URL %q", raw)
	}
	scheme, port := "tcp", "1883"
	switch u.Scheme {
	case "mqtt", "tcp":
	case "mqtts", "ssl", "tls":
		scheme, port = "ssl", "8883"
	default:
		return "", fmt.Errorf("unsupported MQTT scheme %q (use mqtt:// or mqtts://)", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User(u.User.Username())
	return u.String()
}

// connect dials the broker. With lwt, the broker marks LanHound offline
// in HA if the connection drops.
func connect(c Config, clientID string, lwt bool) (mqtt.Client, error) {
	addr, err := brokerAddr(c.URL)
	if err != nil {
		return nil, err
	}
	o := mqtt.NewClientOptions().AddBroker(addr).SetClientID(clientID).
		SetConnectTimeout(10 * time.Second).SetAutoReconnect(true).SetMaxReconnectInterval(time.Minute).
		SetOrderMatters(false)
	user, pass := c.Username, c.Password
	if u, err := url.Parse(c.URL); err == nil && u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if user != "" {
		o.SetUsername(user).SetPassword(pass)
	}
	if strings.HasPrefix(addr, "ssl://") {
		o.SetTLSConfig(&tls.Config{InsecureSkipVerify: c.Insecure}) //nolint:gosec // opt-in for self-signed brokers
	}
	if lwt {
		o.SetWill(statusTopic, "offline", 1, true)
	}
	cl := mqtt.NewClient(o)
	tok := cl.Connect()
	if !tok.WaitTimeout(15 * time.Second) {
		return nil, errors.New("MQTT connect timed out")
	}
	if err := tok.Error(); err != nil {
		return nil, fmt.Errorf("MQTT connect: %w", err)
	}
	return cl, nil
}

type mqttPublisher struct{ c mqtt.Client }

func (p mqttPublisher) Publish(topic string, retained bool, payload []byte) error {
	tok := p.c.Publish(topic, 1, retained, payload)
	if !tok.WaitTimeout(10 * time.Second) {
		return errors.New("MQTT publish timed out")
	}
	return tok.Error()
}

// Run keeps the bridge connected while enabled, until ctx is done.
func (b *Bridge) Run(ctx context.Context) {
	for {
		b.mu.Lock()
		cfg := b.effective()
		b.mu.Unlock()
		if cfg.Enabled {
			b.session(ctx, cfg)
		} else {
			b.setStatus(func(s *Status) { s.Connected, s.LastError, s.Devices = false, "", 0 })
		}
		select {
		case <-ctx.Done():
			return
		case <-b.reload:
		case <-time.After(30 * time.Second): // retry a failed connect
		}
	}
}

func (b *Bridge) setStatus(f func(*Status)) {
	b.mu.Lock()
	f(&b.status)
	b.mu.Unlock()
	b.hub.Publish("hass", b.Status())
}

// session runs one connection until ctx ends or the config changes.
func (b *Bridge) session(ctx context.Context, cfg Config) {
	cl, err := connect(cfg, "lanhound-"+strconv.FormatInt(time.Now().Unix()%1e6, 10), true)
	if err != nil {
		b.failures.Fail(lg(), "connect", "cannot connect to MQTT broker", err, "broker", redactURL(cfg.URL))
		b.setStatus(func(s *Status) { s.Connected, s.LastError = false, err.Error() })
		return
	}
	defer func() {
		_ = mqttPublisher{cl}.Publish(statusTopic, true, []byte("offline"))
		cl.Disconnect(250)
		b.setStatus(func(s *Status) { s.Connected = false })
	}()
	b.failures.OK(lg(), "connect", "MQTT broker reachable again", "broker", redactURL(cfg.URL))
	lg().Info("connected to MQTT broker", "broker", redactURL(cfg.URL))
	b.mu.Lock()
	b.published = map[int64]string{}
	b.mu.Unlock()

	events, cancel := b.hub.Subscribe()
	// cancel is replaced on resubscribe; release whichever is current.
	defer func() { cancel() }()
	p := mqttPublisher{cl}
	if err := b.sync(p, cfg); err != nil {
		b.setStatus(func(s *Status) { s.LastError = err.Error() })
	} else {
		b.setStatus(func(s *Status) { s.Connected, s.LastError = true, "" })
	}

	stats := time.NewTicker(5 * time.Second)
	defer stats.Stop()
	dirty := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.reload:
			select { // let Run pick the new config up
			case b.reload <- struct{}{}:
			default:
			}
			return
		case <-stats.C:
			if dirty {
				dirty = false
				b.publishStats(p)
			}
		case raw, ok := <-events:
			if !ok { // fell behind: resubscribe and resync
				events, cancel = b.hub.Subscribe()
				_ = b.sync(p, cfg)
				continue
			}
			if b.handle(p, cfg, raw) {
				dirty = true
			}
		}
	}
}

// sync publishes the bridge's own entities and every eligible device.
func (b *Bridge) sync(p publisher, cfg Config) error {
	if err := p.Publish(statusTopic, true, []byte("online")); err != nil {
		return err
	}
	for topic, payload := range b.hubEntities(cfg) {
		if err := p.Publish(topic, true, payload); err != nil {
			return err
		}
	}
	for _, v := range b.registry.Devices() {
		if err := b.device(p, cfg, v); err != nil {
			return err
		}
	}
	b.publishStats(p)
	return nil
}

// handle reacts to one hub message; it reports whether stats changed.
func (b *Bridge) handle(p publisher, cfg Config, raw []byte) bool {
	var m struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	switch m.Type {
	case "device":
		var v core.View
		if json.Unmarshal(m.Data, &v) == nil {
			b.logErr(b.device(p, cfg, v))
		}
		return true
	case "remove":
		var r struct {
			ID int64 `json:"id"`
		}
		if json.Unmarshal(m.Data, &r) == nil {
			b.logErr(b.unpublish(p, cfg, r.ID))
		}
		return true
	case "alert":
		var a store.Alert
		if json.Unmarshal(m.Data, &a) == nil {
			b.logErr(b.alert(p, a))
		}
	}
	return false
}

func (b *Bridge) logErr(err error) {
	if err != nil {
		b.failures.Fail(lg(), "publish", "MQTT publish failed", err)
		b.setStatus(func(s *Status) { s.LastError = err.Error() })
		return
	}
	b.failures.OK(lg(), "publish", "MQTT publishing again")
}

func deviceTopic(id int64) string { return base + "/device/" + strconv.FormatInt(id, 10) }

func (b *Bridge) trackerConfigTopic(cfg Config, id int64) string {
	return cfg.Prefix + "/device_tracker/lanhound_" + strconv.FormatInt(id, 10) + "/config"
}

func displayName(v core.View) string {
	for _, s := range []string{v.Name, v.Hostname, v.Model} {
		if s != "" {
			return s
		}
	}
	if v.Vendor != "" && !v.Randomized {
		return v.Vendor + " " + v.MAC[len(v.MAC)-5:]
	}
	return v.MAC
}

// device publishes (or retracts) one device_tracker.
func (b *Bridge) device(p publisher, cfg Config, v core.View) error {
	if !cfg.All && !v.Known {
		return b.unpublish(p, cfg, v.ID)
	}
	topic := deviceTopic(v.ID)
	conns := [][2]string{}
	for _, m := range v.MACs {
		conns = append(conns, [2]string{"mac", m})
	}
	conf := map[string]any{
		"name":                  nil, // the entity takes the device's name
		"unique_id":             "lanhound_" + strconv.FormatInt(v.ID, 10),
		"state_topic":           topic + "/state",
		"json_attributes_topic": topic + "/attributes",
		"payload_home":          "home",
		"payload_not_home":      "not_home",
		"source_type":           "router",
		"availability_topic":    statusTopic,
		"icon":                  "mdi:lan-connect",
		"origin":                map[string]string{"name": "LanHound", "sw": b.version, "url": "https://github.com/playwjj/lanhound"},
		"device": map[string]any{
			"identifiers":  []string{"lanhound_device_" + strconv.FormatInt(v.ID, 10)},
			"name":         displayName(v),
			"connections":  conns,
			"manufacturer": v.Vendor,
			"model":        v.Model,
			"via_device":   "lanhound",
		},
	}
	payload, _ := json.Marshal(conf)
	b.mu.Lock()
	same := b.published[v.ID] == string(payload)
	b.published[v.ID] = string(payload)
	n := len(b.published)
	b.mu.Unlock()
	if !same {
		if err := p.Publish(b.trackerConfigTopic(cfg, v.ID), true, payload); err != nil {
			return err
		}
		b.setStatus(func(s *Status) { s.Devices = n })
	}
	state := "not_home"
	if v.Online {
		state = "home"
	}
	attrs, _ := json.Marshal(map[string]any{
		"ip": v.IP, "ipv6": v.IPv6, "mac": v.MAC, "macs": v.MACs, "hostname": v.Hostname, "vendor": v.Vendor,
		"model": v.Model, "interface": v.Iface, "known": v.Known, "critical": v.Critical,
		"first_seen": v.FirstSeen, "last_seen": v.LastSeen, "note": v.Note, "connection": v.Link,
	})
	if err := p.Publish(topic+"/attributes", true, attrs); err != nil {
		return err
	}
	return p.Publish(topic+"/state", true, []byte(state))
}

// unpublish removes a device's entity (an empty retained config deletes
// it in HA) if it was published.
func (b *Bridge) unpublish(p publisher, cfg Config, id int64) error {
	b.mu.Lock()
	_, was := b.published[id]
	delete(b.published, id)
	n := len(b.published)
	b.mu.Unlock()
	if !was {
		return nil
	}
	b.setStatus(func(s *Status) { s.Devices = n })
	for _, t := range []string{b.trackerConfigTopic(cfg, id), deviceTopic(id) + "/state", deviceTopic(id) + "/attributes"} {
		if err := p.Publish(t, true, nil); err != nil {
			return err
		}
	}
	return nil
}

// hubEntities is LanHound itself: two count sensors and the alert event.
func (b *Bridge) hubEntities(cfg Config) map[string][]byte {
	dev := map[string]any{
		"identifiers": []string{"lanhound"}, "name": "LanHound", "manufacturer": "LanHound",
		"model": "Network watchdog", "sw_version": b.version,
	}
	origin := map[string]string{"name": "LanHound", "sw": b.version, "url": "https://github.com/playwjj/lanhound"}
	mk := func(v map[string]any) []byte {
		v["device"], v["origin"], v["availability_topic"] = dev, origin, statusTopic
		out, _ := json.Marshal(v)
		return out
	}
	return map[string][]byte{
		cfg.Prefix + "/sensor/lanhound_online/config": mk(map[string]any{
			"name": "Devices online", "unique_id": "lanhound_online", "state_topic": base + "/stats",
			"value_template": "{{ value_json.online }}", "unit_of_measurement": "devices", "state_class": "measurement", "icon": "mdi:devices",
		}),
		cfg.Prefix + "/sensor/lanhound_unreviewed/config": mk(map[string]any{
			"name": "Unreviewed devices", "unique_id": "lanhound_unreviewed", "state_topic": base + "/stats",
			"value_template": "{{ value_json.unreviewed }}", "unit_of_measurement": "devices", "icon": "mdi:help-network",
		}),
		cfg.Prefix + "/event/lanhound_alert/config": mk(map[string]any{
			"name": "Alert", "unique_id": "lanhound_alert", "state_topic": base + "/alert", "icon": "mdi:shield-alert",
			"event_types": []string{notify.EventNewDevice, notify.EventARPConflict, notify.EventARPFlood, notify.EventGatewayChanged,
				notify.EventRogueDHCP, notify.EventDeviceOffline, notify.EventDeviceOnline, notify.EventRecognized},
		}),
	}
}

func (b *Bridge) publishStats(p publisher) {
	var online, unreviewed, total int
	for _, v := range b.registry.Devices() {
		total++
		if v.Online {
			online++
		}
		if !v.Known {
			unreviewed++
		}
	}
	raw, _ := json.Marshal(map[string]int{"online": online, "unreviewed": unreviewed, "total": total})
	b.logErr(p.Publish(base+"/stats", true, raw))
}

// alert fires the HA event entity. The payload carries the rendered
// message and the raw alert for templates.
func (b *Bridge) alert(p publisher, a store.Alert) error {
	var m notify.Message
	if err := json.Unmarshal(a.Data, &m); err != nil {
		return err
	}
	lang := "en"
	if b.language != nil {
		lang = b.language()
	}
	raw, _ := json.Marshal(map[string]any{
		"event_type": a.Kind,
		"message":    notify.Render(m, lang, func(s string) string { return s }, "", ""),
		"ip":         m.IP,
		"interface":  m.Interface,
		"devices":    m.Devices,
		"alert_id":   a.ID,
	})
	return p.Publish(base+"/alert", false, raw)
}

func lg() *slog.Logger { return logx.L("hass") }
