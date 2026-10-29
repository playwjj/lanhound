package services

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func listen(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { handle(c); c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestProbe(t *testing.T) {
	sshPort := listen(t, func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-dropbear_2022.83\r\n")) })
	telnetPort := listen(t, func(c net.Conn) {})
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		_, _ = w.Write([]byte("<html><head><title>\n  Synology DiskStation </title></head></html>"))
	}))
	defer web.Close()
	webPort := web.Listener.Addr().(*net.TCPAddr).Port
	// A closed port: grab one and release it.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().(*net.TCPAddr).Port
	l.Close()

	p := Prober{Ports: []Port{{sshPort, "ssh", ""}, {telnetPort, "telnet", ""}, {webPort, "http-alt", "http"}, {closed, "rdp", ""}}, Timeout: 300 * time.Millisecond, Gap: time.Millisecond}
	got := p.Probe(context.Background(), "127.0.0.1")
	if len(got) != 3 {
		t.Fatalf("want 3 open, got %+v", got)
	}
	if got[0].Detail != "SSH-2.0-dropbear_2022.83" {
		t.Errorf("ssh banner %q", got[0].Detail)
	}
	if !got[1].Risky {
		t.Error("telnet must be flagged risky")
	}
	if got[2].Detail != "Synology DiskStation · nginx" || got[2].URL != "http://127.0.0.1:"+strconv.Itoa(webPort)+"/" {
		t.Errorf("web %+v", got[2])
	}
	if Classify(got, Hints{}) != KindNAS {
		t.Errorf("kind %q", Classify(got, Hints{}))
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		svcs []string
		h    Hints
		want string
	}{
		{[]string{"rtsp", "http"}, Hints{Vendor: "Hangzhou Hikvision"}, KindCamera},
		{[]string{"ipp", "http"}, Hints{}, KindPrinter},
		{[]string{"http"}, Hints{Gateway: true}, KindRouter},
		{[]string{"apple-sync"}, Hints{Vendor: "Apple, Inc."}, KindPhone},
		{[]string{"cast"}, Hints{}, KindMedia},
		{[]string{"rdp"}, Hints{}, KindComputer},
		{nil, Hints{Vendor: "Espressif Inc."}, KindIoT},
		{nil, Hints{Vendor: "Apple, Inc."}, ""},
		// Seen on a real home LAN:
		{[]string{"http-alt", "airplay", "apple-sync"}, Hints{Vendor: "Apple, Inc.", Hostname: "AppleTV", Model: "J305AP"}, KindMedia},
		{[]string{"ssh", "http", "https"}, Hints{Vendor: "Quanta Computer Inc.", Hostname: "pw"}, KindRouter}, // dropbear banner below
		{[]string{"http"}, Hints{Vendor: "TP-LINK TECHNOLOGIES CO.,LTD."}, KindRouter},
		{[]string{"airplay", "apple-sync"}, Hints{Vendor: "Apple, Inc.", Hostname: "DC-MacBook-Pro-3"}, KindComputer},
	}
	for _, c := range cases {
		var svcs []Service
		for _, n := range c.svcs {
			sv := Service{Name: n}
			if n == "ssh" && c.h.Hostname == "pw" {
				sv.Detail = "SSH-2.0-dropbear"
			}
			svcs = append(svcs, sv)
		}
		if got := Classify(svcs, c.h); got != c.want {
			t.Errorf("Classify(%v, %+v) = %q, want %q", c.svcs, c.h, got, c.want)
		}
	}
	if s := Summary([]Service{{Port: 80, Name: "http"}, {Port: 22, Name: "ssh"}}); s != "22/ssh, 80/http" {
		t.Errorf("summary %q", s)
	}
}
