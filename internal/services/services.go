// Package services identifies what a device runs by connecting to a
// short list of well-known TCP ports and reading what answers (HTTP
// title and Server header, SSH banner). From that it guesses the kind
// of device — NAS, camera, printer, router… — and flags risky services
// such as Telnet.
//
// This is active probing, so it is off unless the user turns it on, and
// it is gentle: plain TCP connects, one device at a time, a handful of
// ports, short timeouts.
package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Service is one open port.
type Service struct {
	Port   int    `json:"port"`
	Name   string `json:"name"`             // well-known name: ssh, http, smb…
	Detail string `json:"detail,omitempty"` // page title, Server header or banner
	URL    string `json:"url,omitempty"`    // a web UI to open
	Risky  bool   `json:"risky,omitempty"`  // e.g. telnet: unencrypted remote login
}

// Port is a port to probe.
type Port struct {
	Port int
	Name string
	Web  string // "http" or "https" when it usually serves a web UI
}

// DefaultPorts are probed when nothing else is configured.
var DefaultPorts = []Port{
	{21, "ftp", ""}, {22, "ssh", ""}, {23, "telnet", ""}, {80, "http", "http"}, {443, "https", "https"},
	{445, "smb", ""}, {548, "afp", ""}, {554, "rtsp", ""}, {631, "ipp", ""}, {1883, "mqtt", ""},
	{3389, "rdp", ""}, {5000, "http-alt", "http"}, {5001, "https-alt", "https"}, {5900, "vnc", ""},
	{7000, "airplay", ""}, {8008, "cast", ""}, {8080, "http-alt", "http"}, {8123, "home-assistant", "http"},
	{8443, "https-alt", "https"}, {9100, "jetdirect", ""}, {32400, "plex", "http"}, {62078, "apple-sync", ""},
}

// Prober probes one host at a time.
type Prober struct {
	Ports   []Port
	Timeout time.Duration // per connection (default 800ms)
	Gap     time.Duration // pause between ports (default 50ms)
}

// Probe returns the open services of ip.
func (p Prober) Probe(ctx context.Context, ip string) []Service {
	ports := p.Ports
	if ports == nil {
		ports = DefaultPorts
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 800 * time.Millisecond
	}
	gap := p.Gap
	if gap == 0 {
		gap = 50 * time.Millisecond
	}
	var out []Service
	d := net.Dialer{Timeout: timeout}
	for _, pt := range ports {
		if ctx.Err() != nil {
			break
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(pt.Port))
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			time.Sleep(gap)
			continue
		}
		s := Service{Port: pt.Port, Name: pt.Name, Risky: pt.Name == "telnet"}
		if pt.Name == "ssh" || pt.Name == "ftp" {
			s.Detail = banner(c, timeout)
		}
		c.Close()
		if pt.Web != "" {
			s.URL, s.Detail = web(ctx, pt.Web, addr, timeout)
		}
		out = append(out, s)
		time.Sleep(gap)
	}
	return out
}

func banner(c net.Conn, timeout time.Duration) string {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	line, _ := bufio.NewReader(io.LimitReader(c, 256)).ReadString('\n')
	return clean(line)
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// web fetches the front page for its title and Server header.
func web(ctx context.Context, scheme, addr string, timeout time.Duration) (url, detail string) {
	url = scheme + "://" + addr + "/"
	client := &http.Client{
		Timeout: 3 * timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // reading a LAN device's own page title
			Proxy:           nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return url, ""
	}
	req.Header.Set("User-Agent", "LanHound")
	resp, err := client.Do(req)
	if err != nil {
		return url, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var parts []string
	if m := titleRe.FindSubmatch(body); m != nil {
		if t := clean(string(m[1])); t != "" {
			parts = append(parts, t)
		}
	}
	if sv := clean(resp.Header.Get("Server")); sv != "" {
		parts = append(parts, sv)
	}
	return url, strings.Join(parts, " · ")
}

func clean(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}

// Kinds of device.
const (
	KindNAS      = "nas"
	KindCamera   = "camera"
	KindPrinter  = "printer"
	KindRouter   = "router"
	KindComputer = "computer"
	KindPhone    = "phone"
	KindMedia    = "media"
	KindServer   = "server"
	KindIoT      = "iot"
)

// Hints is what else LanHound knows about a device.
type Hints struct {
	Vendor, Hostname, Model string
	Gateway                 bool
}

// Classify guesses the device kind from its services and hints; "" when
// unsure.
func Classify(svcs []Service, h Hints) string {
	has := map[string]bool{}
	text := strings.ToLower(h.Vendor + " " + h.Hostname + " " + h.Model)
	for _, s := range svcs {
		has[s.Name] = true
		text += " " + strings.ToLower(s.Detail)
	}
	contains := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(text, w) {
				return true
			}
		}
		return false
	}
	vendor := strings.ToLower(h.Vendor)
	routerMaker := strings.Contains(vendor, "tp-link") || strings.Contains(vendor, "netgear") || strings.Contains(vendor, "tenda") ||
		strings.Contains(vendor, "mercury") || strings.Contains(vendor, "h3c") || strings.Contains(vendor, "ruijie") ||
		strings.Contains(vendor, "ubiquiti") || strings.Contains(vendor, "mikrotik") || strings.Contains(vendor, "zte")
	web := has["http"] || has["https"]
	switch {
	// Routers, strong evidence: the gateway or router firmware by name.
	case h.Gateway || contains("openwrt", "luci", "routeros", "mikrotik", "asuswrt", "kwrt", "istoreos", "immortalwrt"):
		return KindRouter
	case contains("synology", "diskstation", "qnap", "truenas", "unraid", "nas") || (has["smb"] && (has["afp"] || has["https-alt"])):
		return KindNAS
	// Routers, weaker: OpenWrt's dropbear SSH, or a router maker's web UI.
	case contains("dropbear") || (routerMaker && web && !has["rtsp"]):
		return KindRouter
	case has["rtsp"] || contains("hikvision", "dahua", "ezviz", "imou", "camera", "ipcam", "reolink"):
		return KindCamera
	case has["ipp"] || has["jetdirect"] || contains("printer", "laserjet", "epson", "brother", "canon"):
		return KindPrinter
	// Macs run AirPlay receivers too: name them before media.
	case contains("macbook", "imac", "mac-mini", "macmini", "mac mini", "desktop-", "laptop"):
		return KindComputer
	// Apple TVs also open the iOS sync port: media before phone.
	case has["cast"] || has["airplay"] || has["plex"] || contains("airtunes", "chromecast", "roku", "appletv", "apple tv", "android tv", "xiaomi tv", "fire tv"):
		return KindMedia
	case has["apple-sync"]:
		return KindPhone
	case has["rdp"] || has["vnc"]:
		return KindComputer
	case has["home-assistant"] || has["mqtt"] || (has["ssh"] && web):
		return KindServer
	case contains("espressif", "tuya", "yeelink", "xiaomi", "dreame", "tmall", "xiaodu", "shelly", "sonoff"):
		return KindIoT
	}
	return ""
}

// Summary lists open ports compactly ("22/ssh, 80/http").
func Summary(svcs []Service) string {
	parts := make([]string, len(svcs))
	sorted := append([]Service(nil), svcs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Port < sorted[j].Port })
	for i, s := range sorted {
		parts[i] = fmt.Sprintf("%d/%s", s.Port, s.Name)
	}
	return strings.Join(parts, ", ")
}
