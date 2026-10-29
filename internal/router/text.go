package router

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// urlSource fetches a plain-text device table from any URL — a lease
// file published by a router, a cron job's output, a modem page saved by
// a script. Supported formats are detected line by line:
//
//	dnsmasq leases   1730190000 aa:bb:cc:dd:ee:ff 192.168.1.20 phone 01:aa:…
//	/proc/net/arp    192.168.1.20 0x1 0x2 aa:bb:cc:dd:ee:ff * br-lan
//	ip neigh         192.168.1.20 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE
//	arp -a           phone (192.168.1.20) at aa:bb:cc:dd:ee:ff [ether] on br-lan
//	CSV              mac,ip,hostname (any column order, header optional)
type urlSource struct {
	cfg    Config
	client *http.Client
}

func newURLSource(cfg Config) *urlSource {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user opted in
	}
	return &urlSource{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second, Transport: tr}}
}

func (u *urlSource) Fetch(ctx context.Context) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	if u.cfg.Username != "" || u.cfg.Password != "" {
		req.SetBasicAuth(u.cfg.Username, u.cfg.Password)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", u.cfg.URL, resp.StatusCode)
	}
	entries, err := ParseText(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s: no devices found (unrecognized format?)", u.cfg.URL)
	}
	return entries, nil
}

// ParseText reads a device table in any of the supported formats.
func ParseText(r io.Reader) ([]Entry, error) {
	var entries []Entry
	var csvLines []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ",") {
			csvLines = append(csvLines, line)
			continue
		}
		if e, ok := parseLine(strings.Fields(line)); ok {
			entries = append(entries, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(csvLines) > 0 {
		entries = append(entries, parseCSV(csvLines)...)
	}
	return merge(entries), nil
}

func parseLine(f []string) (Entry, bool) {
	switch {
	// dnsmasq: expiry mac ip hostname [client-id]
	case len(f) >= 4 && isNumber(f[0]) && isMAC(f[1]) && net.ParseIP(f[2]) != nil:
		return Entry{MAC: mac(f[1]), IP: net.ParseIP(f[2]), Hostname: f[3]}, true
	// /proc/net/arp: ip hwtype flags mac mask device (flags 0x0 = incomplete)
	case len(f) >= 6 && net.ParseIP(f[0]) != nil && strings.HasPrefix(f[1], "0x") && isMAC(f[3]):
		if f[2] == "0x0" {
			return Entry{}, false
		}
		return Entry{MAC: mac(f[3]), IP: net.ParseIP(f[0])}, true
	// ip neigh: ip dev X lladdr mac STATE
	case len(f) >= 5 && net.ParseIP(f[0]) != nil:
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "lladdr" && isMAC(f[i+1]) {
				state := f[len(f)-1]
				if state == "FAILED" || state == "INCOMPLETE" {
					return Entry{}, false
				}
				return Entry{MAC: mac(f[i+1]), IP: net.ParseIP(f[0])}, true
			}
		}
	// arp -a: name (ip) at mac ...
	case len(f) >= 4 && strings.HasPrefix(f[1], "(") && f[2] == "at" && isMAC(f[3]):
		ip := net.ParseIP(strings.Trim(f[1], "()"))
		name := f[0]
		if name == "?" {
			name = ""
		}
		return Entry{MAC: mac(f[3]), IP: ip, Hostname: name}, true
	}
	return Entry{}, false
}

// parseCSV finds the MAC, IP and name columns by header or by content.
func parseCSV(lines []string) []Entry {
	rd := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil
	}
	macCol, ipCol, nameCol := -1, -1, -1
	start := 0
	for i, h := range rows[0] {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "mac", "macaddr", "mac_address", "mac address", "hwaddr":
			macCol = i
		case "ip", "ipaddr", "ip_address", "ip address", "ipv4":
			ipCol = i
		case "name", "hostname", "host", "device", "device name":
			nameCol = i
		}
	}
	if macCol >= 0 {
		start = 1
	}
	var out []Entry
	for _, row := range rows[start:] {
		var e Entry
		for i, v := range row {
			v = strings.TrimSpace(v)
			switch {
			case i == macCol || (macCol < 0 && e.MAC == nil && isMAC(v)):
				e.MAC = mac(v)
			case i == ipCol || (ipCol < 0 && e.IP == nil && net.ParseIP(v) != nil):
				e.IP = net.ParseIP(v)
			case i == nameCol || (nameCol < 0 && e.Hostname == "" && v != "" && !isMAC(v) && net.ParseIP(v) == nil):
				e.Hostname = v
			}
		}
		if e.MAC != nil {
			out = append(out, e)
		}
	}
	return out
}

func isNumber(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func normalizeMAC(s string) string { return strings.ReplaceAll(s, "-", ":") }

func isMAC(s string) bool {
	hw, err := net.ParseMAC(normalizeMAC(s))
	return err == nil && len(hw) == 6
}

func mac(s string) net.HardwareAddr {
	hw, _ := net.ParseMAC(normalizeMAC(s))
	return hw
}
