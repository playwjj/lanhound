// Package router reads device tables from routers and modems: devices
// LanHound cannot reach with ARP (another subnet behind the router, a
// guest network, the ISP modem's side of a double NAT) and DHCP
// hostnames for the ones it can.
//
// Sources are opt-in and configured in the web UI. LanHound only reads;
// it never changes anything on the router.
package router

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Source kinds.
const (
	KindOpenWrt = "openwrt" // LuCI's ubus JSON-RPC endpoint
	KindURL     = "url"     // any URL serving a lease file, ARP table or CSV
)

// Config is one configured source.
type Config struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
	// Insecure skips TLS verification: routers mostly serve self-signed
	// certificates on their LAN address.
	Insecure bool `json:"insecure,omitempty"`
}

// Entry is one device a router knows about.
type Entry struct {
	MAC      net.HardwareAddr
	IP       net.IP // may be nil
	Hostname string
	// Wireless is set when the router reports the device associated to
	// one of its own Wi-Fi radios.
	Wireless *Wireless
}

// Wireless describes a Wi-Fi association.
type Wireless struct {
	Band   string `json:"band,omitempty"`   // "2.4 GHz", "5 GHz", "6 GHz"
	Signal int    `json:"signal,omitempty"` // dBm
	Radio  string `json:"radio,omitempty"`  // the AP interface, e.g. phy0-ap0
}

// Source fetches a device table.
type Source interface {
	Fetch(ctx context.Context) ([]Entry, error)
}

// New builds the source for cfg.
func New(cfg Config) (Source, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("router %q: URL is required", cfg.Label)
	}
	switch cfg.Kind {
	case KindOpenWrt:
		return newOpenWrt(cfg), nil
	case KindURL:
		return newURLSource(cfg), nil
	}
	return nil, fmt.Errorf("router %q: unknown kind %q", cfg.Label, cfg.Kind)
}

// merge folds duplicate MACs (a lease and a neighbour entry for the same
// device) into one entry, preferring a non-empty hostname and IP.
func merge(entries []Entry) []Entry {
	idx := map[string]int{}
	var out []Entry
	for _, e := range entries {
		if len(e.MAC) != 6 || e.MAC[0]&0x01 != 0 || isZero(e.MAC) {
			continue
		}
		e.Hostname = cleanHostname(e.Hostname)
		if e.IP != nil {
			e.IP = e.IP.To4() // IPv4 only for now
		}
		k := e.MAC.String()
		if i, ok := idx[k]; ok {
			if out[i].Hostname == "" {
				out[i].Hostname = e.Hostname
			}
			if out[i].IP == nil {
				out[i].IP = e.IP
			}
			if out[i].Wireless == nil {
				out[i].Wireless = e.Wireless
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, e)
	}
	return out
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// cleanHostname drops placeholders routers use for "no name".
func cleanHostname(s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "*", "-", "?", "unknown", "Unknown":
		return ""
	}
	r := []rune(s)
	if len(r) > 63 {
		r = r[:63]
	}
	return string(r)
}
