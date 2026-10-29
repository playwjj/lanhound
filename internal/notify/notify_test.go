package notify

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var sample = Message{Event: EventNewDevice, Devices: []DeviceInfo{{
	ID: 7, Hostname: "Galaxy<S24>", Vendor: "Samsung Electronics", IP: "192.168.2.31",
	MAC: "d4:a6:51:00:00:01", Interface: "eth0", FirstSeen: time.Date(2026, 10, 29, 14, 2, 0, 0, time.Local),
}}}

func TestRenderHTMLEscapes(t *testing.T) {
	got := Render(sample, "en", html.EscapeString, "<b>", "</b>")
	for _, want := range []string{"<b>🐕 New device on your network</b>", "<b>Galaxy&lt;S24&gt;</b> · Samsung Electronics", "IP: 192.168.2.31", "First seen: 2026-10-29 14:02"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderChineseAndHints(t *testing.T) {
	m := Message{Event: EventNewDevice}
	for i := 0; i < 12; i++ {
		m.Devices = append(m.Devices, DeviceInfo{MAC: "da:00:00:00:00:01", Randomized: true, SameAs: "妈妈的手机", FirstSeen: time.Now()})
	}
	got := Render(m, "zh", func(s string) string { return s }, "", "")
	for _, want := range []string{"12 台新设备", "未知设备", "随机 MAC", "很可能是“妈妈的手机”换了随机 MAC", "另有 2 台"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSendTelegramAndWebhook(t *testing.T) {
	var tgBody, hookBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/botTOKEN123/sendMessage":
			_ = json.Unmarshal(b, &tgBody)
		case "/hook":
			_ = json.Unmarshal(b, &hookBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := Settings{TelegramToken: "TOKEN123", TelegramChatID: "42", TelegramAPI: srv.URL, WebhookURL: srv.URL + "/hook"}
	if err := Send(context.Background(), s, sample); err != nil {
		t.Fatal(err)
	}
	if tgBody["chat_id"] != "42" || tgBody["parse_mode"] != "HTML" {
		t.Fatalf("telegram body %v", tgBody)
	}
	if hookBody["event"] != EventNewDevice || !strings.Contains(hookBody["text"].(string), "Galaxy<S24>") {
		t.Fatalf("webhook body %v", hookBody)
	}
	if devs := hookBody["devices"].([]any); len(devs) != 1 {
		t.Fatalf("webhook devices %v", devs)
	}
}

func TestSendErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"ok":false,"description":"Unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := Send(context.Background(), Settings{TelegramToken: "SECRET", TelegramChatID: "1", TelegramAPI: srv.URL}, sample)
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
	if err := Send(context.Background(), Settings{}, sample); err == nil {
		t.Fatal("unconfigured send should fail")
	}
}

func TestRenderSecurityEvents(t *testing.T) {
	plain := func(s string) string { return s }
	gw := DeviceInfo{MAC: "34:f7:16:57:4b:12", IP: "192.168.2.1", Vendor: "TP-LINK", Name: "Router"}
	evil := DeviceInfo{MAC: "02:00:00:00:00:66", IP: "192.168.2.1", Randomized: true}
	cases := []struct {
		m    Message
		lang string
		want []string
	}{
		{Message{Event: EventARPConflict, IP: "192.168.2.1", Gateway: true, Devices: []DeviceInfo{gw, evil}}, "en",
			[]string{"Possible ARP spoofing of your gateway 192.168.2.1", "Router · TP-LINK · 34:f7:16:57:4b:12 (192.168.2.1)", "Unknown device · 02:00:00:00:00:66"}},
		{Message{Event: EventARPFlood, Count: 57, Seconds: 10, Devices: []DeviceInfo{evil}}, "zh", []string{"大量发送 ARP", "57 个未经请求的 ARP 包，用时 10 秒"}},
		{Message{Event: EventGatewayChanged, IP: "192.168.2.1", Devices: []DeviceInfo{gw, evil}}, "en", []string{"Before: Router", "Now: Unknown device"}},
		{Message{Event: EventRogueDHCP, Interface: "eth0", IP: "192.168.2.123", Trusted: []string{"192.168.2.1"}, Devices: []DeviceInfo{{MAC: "60:eb:69:e3:3a:4b", Hostname: "pw"}}}, "zh",
			[]string{"eth0 上出现了意外的 DHCP 服务器", "服务器: pw", "已知服务器: 192.168.2.1"}},
		{Message{Event: EventDeviceOnline, Seconds: 3*3600 + 12*60, Devices: []DeviceInfo{{Name: "NAS", MAC: "00:11:32:aa:bb:02"}}}, "zh", []string{"NAS 恢复在线", "离线时长 3小时12分"}},
		{Message{Event: EventDeviceOffline, Devices: []DeviceInfo{{Name: "NAS", MAC: "00:11:32:aa:bb:02"}}}, "en", []string{"🔴 NAS went offline"}},
	}
	for _, c := range cases {
		got := Render(c.m, c.lang, plain, "", "")
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in:\n%s", c.m.Event, w, got)
			}
		}
	}
}

func TestWants(t *testing.T) {
	s := Settings{NotifyNew: true, NotifySecurity: false, NotifyCritical: true}
	if !s.Wants(EventNewDevice) || s.Wants(EventRogueDHCP) || !s.Wants(EventDeviceOffline) || !s.Wants(EventTest) {
		t.Fatal("category switches wrong")
	}
}
