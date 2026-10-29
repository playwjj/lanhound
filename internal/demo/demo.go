// Package demo simulates a home network so the web UI can be tried —
// and screenshotted — on any OS without raw-socket access.
package demo

import (
	"context"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/scanner"
)

type host struct {
	mac, ip, iface, name, src, model string
	flaky                            bool // drops off now and then (phones)
	joinAfter                        time.Duration
}

var hosts = []host{
	{"00:0a:eb:12:34:01", "192.168.2.1", "eth0", "", "", "", false, 0},
	{"00:11:32:aa:bb:02", "192.168.2.10", "eth0", "DiskStation", passive.SrcMDNS, "DS920+", false, 0},
	{"b8:27:eb:3c:4d:03", "192.168.2.11", "eth0", "homeassistant", passive.SrcDHCP, "", false, 0},
	{"f4:f5:d8:01:02:04", "192.168.2.20", "eth0", "Living-Room-TV", passive.SrcMDNS, "Chromecast Ultra", false, 0},
	{"3c:22:fb:9a:8b:05", "192.168.2.21", "eth0", "MacBook-Pro", passive.SrcDHCP, "MacBookPro18,3", true, 0},
	{"00:00:f0:22:33:06", "192.168.2.31", "eth0", "Galaxy-S24", passive.SrcDHCP, "", true, 0},
	{"24:0a:c4:56:78:07", "192.168.2.87", "eth0", "Kitchen-Plug", passive.SrcDHCP, "", false, 0},
	{"24:0a:c4:56:78:08", "192.168.2.88", "eth0", "", "", "", false, 0},
	{"00:bc:99:aa:00:09", "192.168.2.40", "eth0", "", "", "Linux/3.10 UPnP/1.0 Hikvision", false, 0},
	{"00:0c:6e:10:20:0a", "192.168.2.50", "eth0", "DESKTOP-7Q2LM", passive.SrcNBNS, "", false, 0},
	{"5a:1c:9e:44:55:0b", "192.168.2.52", "eth0", "Moms-iPhone", passive.SrcDHCP, "", true, 0},
	{"00:0d:4b:10:20:0c", "192.168.2.60", "eth0", "", "", "Linux/4.9 UPnP/1.0 Roku/11.5", false, 0},
	{"e8:4e:06:00:11:0d", "10.0.0.2", "wlan0", "", "", "", false, 0},
	{"7c:49:eb:0a:0b:0e", "10.0.0.15", "wlan0", "yeelink-light", passive.SrcDHCP, "", false, 0},
	{"64:90:c1:33:22:0f", "10.0.0.16", "wlan0", "", "", "", false, 0},
	// Joins after startup: a stranger, then Mom's phone with a fresh random MAC.
	{"94:e9:79:ab:cd:10", "192.168.2.77", "eth0", "android-4f2a9c", passive.SrcDHCP, "", false, 40 * time.Second},
	{"2e:0f:7a:61:3b:11", "192.168.2.53", "eth0", "Moms-iPhone", passive.SrcDHCP, "", false, 70 * time.Second},
}

// Scanner is a fake discovery engine.
type Scanner struct {
	onSighting func(passive.Sighting)
	onStatus   func()
	firstRound chan struct{}

	mu     sync.Mutex
	status map[string]*scanner.Status
	sweep  chan struct{}
}

// New returns a fake scanner.
func New(onSighting func(passive.Sighting), onStatus func()) *Scanner {
	return &Scanner{
		onSighting: onSighting,
		onStatus:   onStatus,
		firstRound: make(chan struct{}),
		sweep:      make(chan struct{}, 1),
		status: map[string]*scanner.Status{
			"eth0":  {Interface: "eth0", Network: "192.168.2.0/24", IP: "192.168.2.5", MAC: "02:42:c0:a8:02:05", Hosts: 253},
			"wlan0": {Interface: "wlan0", Network: "10.0.0.0/24", IP: "10.0.0.5", MAC: "02:42:0a:00:00:05", Hosts: 253},
		},
	}
}

// FirstRound is closed after the first simulated sweep.
func (s *Scanner) FirstRound() <-chan struct{} { return s.firstRound }

// Run simulates sweeps until ctx is done.
func (s *Scanner) Run(ctx context.Context) {
	start := time.Now()
	s.round(start, true)
	close(s.firstRound)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.sweep:
		}
		s.round(start, false)
	}
}

func (s *Scanner) round(start time.Time, first bool) {
	s.setSweeping(true)
	time.Sleep(800 * time.Millisecond)
	counts := map[string]int{}
	for _, h := range hosts {
		if time.Since(start) < h.joinAfter {
			continue
		}
		if h.flaky && !first && rand.IntN(4) == 0 {
			continue
		}
		hw, _ := net.ParseMAC(h.mac)
		sg := passive.Sighting{Iface: h.iface, MAC: hw, IP: net.ParseIP(h.ip).To4(), Source: passive.SrcARPReply, At: time.Now()}
		if h.name != "" {
			sg.Hostname, sg.HostnameSource = h.name, h.src
		}
		sg.Model = h.model
		s.onSighting(sg)
		counts[h.iface]++
	}
	s.mu.Lock()
	for name, st := range s.status {
		st.Sweeping, st.LastSweep, st.LastReplies = false, time.Now(), counts[name]
	}
	s.mu.Unlock()
	s.onStatus()
}

func (s *Scanner) setSweeping(v bool) {
	s.mu.Lock()
	for _, st := range s.status {
		st.Sweeping = v
	}
	s.mu.Unlock()
	s.onStatus()
}

// Status implements web.Scanner.
func (s *Scanner) Status() []scanner.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return []scanner.Status{*s.status["eth0"], *s.status["wlan0"]}
}

// Skipped implements web.Scanner.
func (s *Scanner) Skipped() []string { return nil }

// Sweep implements web.Scanner.
func (s *Scanner) Sweep() {
	select {
	case s.sweep <- struct{}{}:
	default:
	}
}
