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
		m.Devices = append(m.Devices, DeviceInfo{MAC: "da:00:00:00:00:01", Randomized: true, SameNameAs: "妈妈的手机", FirstSeen: time.Now()})
	}
	got := Render(m, "zh", func(s string) string { return s }, "", "")
	for _, want := range []string{"12 台新设备", "未知设备", "随机 MAC", "与“妈妈的手机”主机名相同", "另有 2 台"} {
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
