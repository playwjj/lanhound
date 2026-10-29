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
	if r.StatusCode != 200 || !strings.HasPrefix(string(b), "\ufeffname,hostname,ip") || !strings.Contains(string(b), "Plug,,192.168.2.9,24:0a:c4:00:00:01") {
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
