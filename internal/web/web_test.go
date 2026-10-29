package web

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/scanner"
	"github.com/playwjj/lanhound/internal/security"
	"github.com/playwjj/lanhound/internal/store"
)

type fakeScanner struct{ swept int }

func (f *fakeScanner) Status() []scanner.Status {
	return []scanner.Status{{Interface: "eth0", Network: "192.168.2.0/24"}}
}
func (f *fakeScanner) Skipped() []string { return nil }
func (f *fakeScanner) Sweep()            { f.swept++ }

func setup(t *testing.T, password string) (*httptest.Server, *core.Registry, *fakeScanner) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
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
	sc := &fakeScanner{}
	srv := &Server{Registry: reg, Settings: set, Hub: hub, Scanner: sc, Version: "test", Interval: time.Minute, Password: password}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, reg, sc
}

func do(t *testing.T, method, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

var csrf = map[string]string{"X-LanHound": "1"}

func TestDevicesAPI(t *testing.T) {
	ts, reg, sc := setup(t, "")
	reg.Observe(passive.Sighting{MAC: net.HardwareAddr{0x24, 0x0a, 0xc4, 0, 0, 1}, IP: net.IPv4(192, 168, 2, 9), Iface: "eth0"})

	var devs []core.View
	_ = json.NewDecoder(do(t, "GET", ts.URL+"/api/devices", "", nil).Body).Decode(&devs)
	if len(devs) != 1 || devs[0].Vendor == "" {
		t.Fatalf("devices %+v", devs)
	}
	id := devs[0].ID

	if r := do(t, "PATCH", ts.URL+"/api/devices/"+itoa(id), `{"name":"Plug"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without X-LanHound must be refused, got %d", r.StatusCode)
	}
	r := do(t, "PATCH", ts.URL+"/api/devices/"+itoa(id), `{"name":"Plug","known":true}`, csrf)
	var v core.View
	_ = json.NewDecoder(r.Body).Decode(&v)
	if r.StatusCode != 200 || v.Name != "Plug" || !v.Known {
		t.Fatalf("patch %d %+v", r.StatusCode, v)
	}
	if r := do(t, "GET", ts.URL+"/api/devices/999", "", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown device: %d", r.StatusCode)
	}
	if r := do(t, "GET", ts.URL+"/api/devices/"+itoa(id)+"/history", "", nil); r.StatusCode != 200 {
		t.Fatalf("history: %d", r.StatusCode)
	}
	r = do(t, "GET", ts.URL+"/api/devices.csv", "", nil)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.HasPrefix(string(b), "\ufeffname,hostname,ip,ipv6") || !strings.Contains(string(b), "Plug,,192.168.2.9,,24:0a:c4:00:00:01") {
		t.Fatalf("csv %d:\n%s", r.StatusCode, b)
	}
	if got := csvSafe("=HYPERLINK(1)"); got != "'=HYPERLINK(1)" {
		t.Fatalf("csvSafe = %q", got)
	}
	do(t, "POST", ts.URL+"/api/scan", "", csrf)
	if sc.swept != 1 {
		t.Fatal("scan not triggered")
	}
	if r := do(t, "DELETE", ts.URL+"/api/devices/"+itoa(id), "", csrf); r.StatusCode != 200 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
}

func TestSettingsAPI(t *testing.T) {
	ts, _, _ := setup(t, "")
	r := do(t, "PUT", ts.URL+"/api/settings", `{"telegramToken":"123456:SECRETTOKEN","telegramChatId":"5","notifyNew":true}`, csrf)
	var p core.PublicSettings
	_ = json.NewDecoder(r.Body).Decode(&p)
	if strings.Contains(p.TelegramToken, "SECRET") || p.TelegramChatID != "5" {
		t.Fatalf("settings leak or not saved: %+v", p)
	}
	var st Status
	_ = json.NewDecoder(do(t, "GET", ts.URL+"/api/status", "", nil).Body).Decode(&st)
	if !st.Notify || st.Version != "test" || len(st.Interfaces) != 1 {
		t.Fatalf("status %+v", st)
	}
}

func TestPassword(t *testing.T) {
	ts, _, _ := setup(t, "hunter2")
	if r := do(t, "GET", ts.URL+"/api/devices", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", r.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/devices", nil)
	req.SetBasicAuth("admin", "hunter2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("authorized request failed: %v %v", err, resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginLockout(t *testing.T) {
	ts, _, _ := setup(t, "hunter2")
	try := func(pass string) int {
		req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
		req.SetBasicAuth("", pass)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Requests without credentials (a browser's first try) don't count.
	for i := 0; i < 10; i++ {
		do(t, "GET", ts.URL+"/api/status", "", nil)
	}
	if try("hunter2") != 200 {
		t.Fatal("credential-less requests must not lock the user out")
	}
	for i := 0; i < maxFailures; i++ {
		if c := try("guess"); c != 401 {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	if c := try("hunter2"); c != http.StatusTooManyRequests {
		t.Fatalf("locked out client got %d with the right password", c)
	}
}

func TestLimiterExpires(t *testing.T) {
	l := newLimiter()
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < maxFailures-1; i++ {
		l.fail("10.0.0.9")
	}
	now = now.Add(failureWindow + time.Minute) // old failures age out
	l.fail("10.0.0.9")
	if _, locked := l.locked("10.0.0.9"); locked {
		t.Fatal("failures outside the window must not add up")
	}
	for i := 0; i < maxFailures; i++ {
		l.fail("10.0.0.9")
	}
	if _, locked := l.locked("10.0.0.9"); !locked {
		t.Fatal("should be locked")
	}
	now = now.Add(lockout + time.Second)
	if _, locked := l.locked("10.0.0.9"); locked {
		t.Fatal("lockout must expire")
	}
}

func TestEventsSnapshotAndUpdates(t *testing.T) {
	ts, reg, _ := setup(t, "")
	resp, err := http.Get(ts.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rd := bufio.NewReader(resp.Body)
	next := func() core.Message {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(line, "data: ") {
				var m core.Message
				_ = json.Unmarshal([]byte(line[6:]), &m)
				return m
			}
		}
	}
	if m := next(); m.Type != "snapshot" {
		t.Fatalf("first message %q", m.Type)
	}
	reg.Observe(passive.Sighting{MAC: net.HardwareAddr{0x24, 0x0a, 0xc4, 0, 0, 2}, IP: net.IPv4(192, 168, 2, 10), Iface: "eth0"})
	if m := next(); m.Type != "device" {
		t.Fatalf("want device update, got %q", m.Type)
	}
}

func TestStaticFallback(t *testing.T) {
	ts, _, _ := setup(t, "")
	r := do(t, "GET", ts.URL+"/some/client/route", "", nil)
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("SPA fallback: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if r := do(t, "GET", ts.URL+"/api/nope", "", nil); r.StatusCode != 404 {
		t.Fatalf("unknown API path: %d", r.StatusCode)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

type fakeGuard struct{ trusted []string }

func (f *fakeGuard) Gateways() map[string][]string {
	return map[string][]string{"eth0": {"192.168.2.1"}}
}
func (f *fakeGuard) TrustDHCP(iface, key string) error {
	f.trusted = append(f.trusted, iface+" "+key)
	return nil
}

func TestAlertsAPI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	set, _ := core.NewSettings(st, notify.Settings{})
	hub := core.NewHub()
	reg, _ := core.NewRegistry(core.Options{Store: st, Hub: hub, Settings: set})
	g := &fakeGuard{}
	ts := httptest.NewServer((&Server{Registry: reg, Settings: set, Hub: hub, Scanner: &fakeScanner{}, Security: g}).Handler())
	defer ts.Close()

	rogue, _ := net.ParseMAC("e4:95:6e:40:11:22")
	reg.RaiseFinding(security.Finding{Event: notify.EventRogueDHCP, Interface: "eth0", IP: net.IPv4(192, 168, 8, 1), MACs: []net.HardwareAddr{rogue}, Key: "192.168.8.1/e4:95:6e:40:11:22"})
	reg.RaiseFinding(security.Finding{Event: notify.EventARPFlood, Interface: "eth0", MACs: []net.HardwareAddr{rogue}, Count: 20})

	var list []core.AlertView
	_ = json.NewDecoder(do(t, "GET", ts.URL+"/api/alerts", "", nil).Body).Decode(&list)
	if len(list) != 2 || list[0].Kind != notify.EventARPFlood || list[1].Text["en"].Title == "" || list[1].Text["zh"].Labels[0] != "服务器" {
		t.Fatalf("alerts %+v", list)
	}
	if r := do(t, "POST", ts.URL+"/api/alerts/"+itoa(list[0].ID)+"/trust", "", csrf); r.StatusCode != 400 {
		t.Fatalf("trusting a non-DHCP alert: %d", r.StatusCode)
	}
	if r := do(t, "POST", ts.URL+"/api/alerts/"+itoa(list[1].ID)+"/trust", "", csrf); r.StatusCode != 200 {
		t.Fatalf("trust: %d", r.StatusCode)
	}
	if len(g.trusted) != 1 || g.trusted[0] != "eth0 192.168.8.1/e4:95:6e:40:11:22" {
		t.Fatalf("trusted %v", g.trusted)
	}
	var st2 Status
	_ = json.NewDecoder(do(t, "GET", ts.URL+"/api/status", "", nil).Body).Decode(&st2)
	if st2.Gateways["eth0"][0] != "192.168.2.1" {
		t.Fatalf("gateways %v", st2.Gateways)
	}
}

func TestIngestAPI(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "i.db"))
	defer st.Close()
	set, _ := core.NewSettings(st, notify.Settings{})
	hub := core.NewHub()
	reg, _ := core.NewRegistry(core.Options{Store: st, Hub: hub, Settings: set})
	probes, _ := core.NewProbes(st, func(s passive.Sighting, _ bool) { reg.Observe(s) })
	ts := httptest.NewServer((&Server{Registry: reg, Settings: set, Hub: hub, Scanner: &fakeScanner{}, Probes: probes, Password: "ui-pass"}).Handler())
	defer ts.Close()

	add := func() string {
		req, _ := http.NewRequest("POST", ts.URL+"/api/probes", strings.NewReader(`{"name":"guest"}`))
		req.SetBasicAuth("", "ui-pass")
		req.Header.Set("X-LanHound", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct{ Token string }
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out.Token
	}
	token := add()
	if token == "" {
		t.Fatal("no token")
	}
	body := `{"version":"v9","interfaces":[{"interface":"eth0","network":"192.168.50.0/24"}],"sightings":[{"iface":"eth0","mac":"24:0a:c4:00:00:50","ip":"192.168.50.20","source":"arp-reply"}]}`
	// The UI password does not apply to /api/ingest; the probe token does.
	if r := do(t, "POST", ts.URL+"/api/ingest", body, map[string]string{"Authorization": "Bearer nope", "X-LanHound": "agent"}); r.StatusCode != 401 {
		t.Fatalf("bad token: %d", r.StatusCode)
	}
	if r := do(t, "POST", ts.URL+"/api/ingest", body, map[string]string{"Authorization": "Bearer " + token, "X-LanHound": "agent"}); r.StatusCode != 200 {
		t.Fatalf("ingest: %d", r.StatusCode)
	}
	if devs := reg.Devices(); len(devs) != 1 || devs[0].Iface != "guest/eth0" {
		t.Fatalf("devices %+v", devs)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.SetBasicAuth("", "ui-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st2 Status
	_ = json.NewDecoder(resp.Body).Decode(&st2)
	if len(st2.Interfaces) != 2 || st2.Interfaces[1].Interface != "guest/eth0" || len(st2.Probes) != 1 || !st2.Probes[0].Online {
		t.Fatalf("status %+v", st2)
	}
}
