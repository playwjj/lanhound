package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeUbus mimics uhttpd-mod-ubus + rpcd: JSON-RPC "call" with a
// session id, status-code results, -32002 for unknown sessions.
type fakeUbus struct {
	mu       sync.Mutex
	sessions map[string]bool
	logins   int
	noHints  bool
}

func (f *fakeUbus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ubus" {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var sid, obj, method string
	_ = json.Unmarshal(req.Params[0], &sid)
	_ = json.Unmarshal(req.Params[1], &obj)
	_ = json.Unmarshal(req.Params[2], &method)
	reply := func(v ...any) { _ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": v}) }

	f.mu.Lock()
	defer f.mu.Unlock()
	if obj == "session" && method == "login" {
		var a map[string]string
		_ = json.Unmarshal(req.Params[3], &a)
		if a["username"] != "root" || a["password"] != "test-only" {
			reply(6)
			return
		}
		f.logins++
		id := strings.Repeat("a", 31) + string(rune('0'+f.logins))
		f.sessions[id] = true
		reply(0, map[string]any{"ubus_rpc_session": id, "timeout": 300})
		return
	}
	if !f.sessions[sid] {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32002, "message": "Access denied"}})
		return
	}
	switch obj + "." + method {
	case "luci-rpc.getDHCPLeases":
		reply(0, map[string]any{
			"dhcp_leases": []map[string]any{
				{"expires": 40000, "hostname": "IPTV-Box", "ipaddr": "192.168.1.50", "macaddr": "00:1e:a0:11:22:33"},
				{"expires": 3000, "hostname": "", "ipaddr": "192.168.1.51", "macaddr": "da:00:00:00:00:51"},
			},
			"dhcp6_leases": []any{},
		})
	case "luci-rpc.getHostHints":
		if f.noHints {
			reply(3)
			return
		}
		reply(0, map[string]any{
			"00:1E:A0:11:22:33": map[string]any{"ipaddrs": []string{"192.168.1.50"}, "ip6addrs": []string{"fe80::1"}},
			"DA:00:00:00:00:51": map[string]any{"ipaddrs": []string{"192.168.1.51"}, "name": "Pixel-8"},
			"AC:84:C6:00:00:60": map[string]any{"ipaddrs": []string{"192.168.1.60"}, "name": "NAS"},
		})
	case "iwinfo.devices":
		if f.noHints {
			reply(3)
			return
		}
		reply(0, map[string]any{"devices": []string{"phy0-ap0", "phy1-ap0"}})
	case "iwinfo.info":
		var a map[string]string
		_ = json.Unmarshal(req.Params[3], &a)
		freq := 2437
		if a["device"] == "phy1-ap0" {
			freq = 5180
		}
		reply(0, map[string]any{"frequency": freq})
	case "iwinfo.assoclist":
		var a map[string]string
		_ = json.Unmarshal(req.Params[3], &a)
		if a["device"] == "phy1-ap0" {
			reply(0, map[string]any{"results": []map[string]any{{"mac": "DA:00:00:00:00:51", "signal": -52}}})
			return
		}
		reply(0, map[string]any{"results": []map[string]any{{"mac": "7C:49:EB:0A:0B:0E", "signal": -71}}})
	default:
		reply(3)
	}
}

func TestOpenWrtFetch(t *testing.T) {
	fake := &fakeUbus{sessions: map[string]bool{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	src, _ := New(Config{Kind: KindOpenWrt, URL: srv.URL, Password: "test-only"})
	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]Entry{}
	for _, e := range got {
		byMAC[e.MAC.String()] = e
	}
	if len(got) != 4 || byMAC["00:1e:a0:11:22:33"].Hostname != "IPTV-Box" || byMAC["da:00:00:00:00:51"].Hostname != "Pixel-8" || byMAC["ac:84:c6:00:00:60"].IP.String() != "192.168.1.60" {
		t.Fatalf("entries %+v", got)
	}
	if w := byMAC["da:00:00:00:00:51"].Wireless; w == nil || w.Band != "5 GHz" || w.Signal != -52 {
		t.Fatalf("phone should be on 5 GHz Wi-Fi: %+v", w)
	}
	if w := byMAC["7c:49:eb:0a:0b:0e"].Wireless; w == nil || w.Band != "2.4 GHz" {
		t.Fatalf("Wi-Fi-only client (no lease) should be listed: %+v", w)
	}
	if byMAC["00:1e:a0:11:22:33"].Wireless != nil {
		t.Fatal("wired IPTV box must not be marked wireless")
	}

	// The session is reused, and renewed transparently when it expires.
	_, _ = src.Fetch(context.Background())
	fake.mu.Lock()
	logins := fake.logins
	fake.sessions = map[string]bool{}
	fake.mu.Unlock()
	if logins != 1 {
		t.Fatalf("logged in %d times for two fetches", logins)
	}
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("expired session not renewed: %v", err)
	}
}

func TestOpenWrtErrors(t *testing.T) {
	fake := &fakeUbus{sessions: map[string]bool{}, noHints: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	bad, _ := New(Config{Kind: KindOpenWrt, URL: srv.URL, Password: "wrong"})
	if _, err := bad.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "wrong username or password") {
		t.Fatalf("err = %v", err)
	}
	// Old LuCI without getHostHints: leases still work.
	ok, _ := New(Config{Kind: KindOpenWrt, URL: srv.URL + "/ubus", Password: "test-only"})
	got, err := ok.Fetch(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("leases-only fetch: %v %+v", err, got)
	}
	notOpenWrt, _ := New(Config{Kind: KindOpenWrt, URL: srv.URL + "/cgi-bin", Password: "x"})
	if _, err := notOpenWrt.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseText(t *testing.T) {
	cases := map[string]struct {
		text string
		want map[string]string // mac → "ip hostname"
	}{
		"dnsmasq": {"1730190000 00:1e:a0:11:22:33 192.168.1.50 IPTV-Box 01:00:1e:a0:11:22:33\n1730190000 da:00:00:00:00:51 192.168.1.51 * *\n",
			map[string]string{"00:1e:a0:11:22:33": "192.168.1.50 IPTV-Box", "da:00:00:00:00:51": "192.168.1.51 "}},
		"proc arp": {"IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.50     0x1         0x2         00:1e:a0:11:22:33     *        br-lan\n192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        br-lan\n",
			map[string]string{"00:1e:a0:11:22:33": "192.168.1.50 "}},
		"ip neigh": {"192.168.1.50 dev br-lan lladdr 00:1e:a0:11:22:33 REACHABLE\n192.168.1.77 dev br-lan  FAILED\n192.168.1.60 dev br-lan lladdr ac:84:c6:00:00:60 STALE\n",
			map[string]string{"00:1e:a0:11:22:33": "192.168.1.50 ", "ac:84:c6:00:00:60": "192.168.1.60 "}},
		"arp -a": {"IPTV-Box (192.168.1.50) at 00:1e:a0:11:22:33 [ether] on br-lan\n? (192.168.1.60) at ac:84:c6:00:00:60 [ether] on br-lan\n",
			map[string]string{"00:1e:a0:11:22:33": "192.168.1.50 IPTV-Box", "ac:84:c6:00:00:60": "192.168.1.60 "}},
		"csv header": {"Hostname,IP Address,MAC Address\nIPTV-Box,192.168.1.50,00-1E-A0-11-22-33\n",
			map[string]string{"00:1e:a0:11:22:33": "192.168.1.50 IPTV-Box"}},
		"csv bare": {"00:1e:a0:11:22:33,192.168.1.50,IPTV-Box\n",
			map[string]string{"00:1e:a0:11:22:33": "192.168.1.50 IPTV-Box"}},
	}
	for name, c := range cases {
		got, err := ParseText(strings.NewReader(c.text))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m := map[string]string{}
		for _, e := range got {
			ip := ""
			if e.IP != nil {
				ip = e.IP.String()
			}
			m[e.MAC.String()] = ip + " " + e.Hostname
		}
		if len(m) != len(c.want) {
			t.Errorf("%s: got %v, want %v", name, m, c.want)
			continue
		}
		for k, v := range c.want {
			if m[k] != v {
				t.Errorf("%s: %s = %q, want %q", name, k, m[k], v)
			}
		}
	}
}

func TestURLSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "p" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte("1730190000 00:1e:a0:11:22:33 192.168.1.50 IPTV-Box *\n"))
	}))
	defer srv.Close()
	src, _ := New(Config{Kind: KindURL, URL: srv.URL, Username: "u", Password: "p"})
	got, err := src.Fetch(context.Background())
	if err != nil || len(got) != 1 || got[0].Hostname != "IPTV-Box" {
		t.Fatalf("%v %+v", err, got)
	}
	noauth, _ := New(Config{Kind: KindURL, URL: srv.URL})
	if _, err := noauth.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}
