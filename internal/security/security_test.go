package security

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/passive"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Setting(k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}
func (s *memStore) SetSetting(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

type harness struct {
	g     *Guard
	st    *memStore
	now   time.Time
	found []Finding
}

func newHarness() *harness {
	h := &harness{st: &memStore{m: map[string]string{}}, now: time.Unix(1_800_000_000, 0)}
	h.g = New(h.st, func(f Finding) { h.found = append(h.found, f) })
	h.g.now = func() time.Time { return h.now }
	h.g.SetGateways(map[string][]net.IP{"eth0": {net.IPv4(192, 168, 2, 1).To4()}})
	return h
}

var (
	router  = "34:f7:16:57:4b:12"
	phoneA  = "da:00:00:00:00:0a"
	phoneB  = "da:00:00:00:00:0b"
	spoofer = "02:00:00:00:00:66"
	rogue   = "60:eb:69:e3:3a:4b"
)

func (h *harness) arp(mac, ip string, opts ...func(*passive.Sighting)) {
	hw, _ := net.ParseMAC(mac)
	s := passive.Sighting{Iface: "eth0", MAC: hw, IP: net.ParseIP(ip).To4(), Source: passive.SrcARPReply, At: h.now}
	for _, o := range opts {
		o(&s)
	}
	h.g.Observe(s)
}

func (h *harness) events() []string {
	var out []string
	for _, f := range h.found {
		out = append(out, f.Event)
	}
	return out
}

func TestHandoverIsNotAConflict(t *testing.T) {
	h := newHarness()
	h.arp(phoneA, "192.168.2.50")
	h.now = h.now.Add(2 * time.Minute)
	h.arp(phoneA, "192.168.2.50")
	// The phone reconnects with a fresh random MAC and DHCP hands back the same IP.
	h.now = h.now.Add(30 * time.Second)
	for i := 0; i < 5; i++ {
		h.arp(phoneB, "192.168.2.50")
		h.now = h.now.Add(time.Minute)
	}
	if len(h.found) != 0 {
		t.Fatalf("handover reported: %v", h.events())
	}
}

func TestGatewaySpoofing(t *testing.T) {
	h := newHarness()
	h.arp(router, "192.168.2.1") // learned as the gateway MAC
	h.now = h.now.Add(time.Minute)
	h.arp(spoofer, "192.168.2.1") // attacker starts claiming the gateway
	if len(h.found) != 0 {
		t.Fatalf("a single newcomer claim is not yet a conflict: %v", h.events())
	}
	h.now = h.now.Add(20 * time.Second)
	h.arp(router, "192.168.2.1") // the real router answers our next sweep
	h.now = h.now.Add(2 * time.Second)
	h.arp(spoofer, "192.168.2.1")
	if len(h.found) != 1 || h.found[0].Event != notify.EventARPConflict || !h.found[0].Gateway {
		t.Fatalf("want one gateway conflict, got %+v", h.found)
	}
	if h.found[0].MACs[0].String() != router || h.found[0].MACs[1].String() != spoofer {
		t.Fatalf("established claimant should come first: %v", h.found[0].MACs)
	}
	// While both claim, no "gateway changed" on top of the conflict.
	if got := h.st.m["security.gateway.eth0.192.168.2.1"]; got != router {
		t.Fatalf("stored gateway MAC = %q", got)
	}
}

func TestGatewayReplaced(t *testing.T) {
	h := newHarness()
	h.arp(router, "192.168.2.1")
	newRouter := "8c:3b:ad:00:00:01"
	h.now = h.now.Add(time.Minute)
	h.arp(newRouter, "192.168.2.1") // old router is still in the claim window
	if len(h.found) != 0 {
		t.Fatalf("too early: %v", h.events())
	}
	h.now = h.now.Add(ClaimWindow + time.Minute)
	h.arp(newRouter, "192.168.2.1")
	if len(h.found) != 1 || h.found[0].Event != notify.EventGatewayChanged || h.found[0].MACs[0].String() != router {
		t.Fatalf("want gateway_changed, got %+v", h.found)
	}
	h.now = h.now.Add(time.Minute)
	h.arp(newRouter, "192.168.2.1")
	if len(h.found) != 1 {
		t.Fatal("gateway change must be reported once")
	}
}

func TestARPFlood(t *testing.T) {
	h := newHarness()
	for i := 0; i < FloodThreshold-1; i++ {
		h.arp(spoofer, "192.168.2.99", func(s *passive.Sighting) { s.Source, s.Gratuitous = passive.SrcARP, true })
	}
	if len(h.found) != 0 {
		t.Fatal("below threshold")
	}
	h.arp(spoofer, "192.168.2.99", func(s *passive.Sighting) { s.Source, s.Gratuitous = passive.SrcARP, true })
	if len(h.found) != 1 || h.found[0].Event != notify.EventARPFlood || h.found[0].Count != FloodThreshold {
		t.Fatalf("want flood, got %+v", h.found)
	}
	// Ordinary requests, however many, are not a flood (routers scan subnets).
	h2 := newHarness()
	for i := 0; i < 300; i++ {
		h2.arp(router, "192.168.2.1", func(s *passive.Sighting) { s.Source = passive.SrcARP })
	}
	if len(h2.found) != 0 {
		t.Fatalf("requests counted as flood: %v", h2.events())
	}
}

func (h *harness) dhcp(mac, serverID string) {
	hw, _ := net.ParseMAC(mac)
	h.g.Observe(passive.Sighting{Iface: "eth0", MAC: hw, IP: net.ParseIP(serverID).To4(), Source: passive.SrcDHCP,
		DHCPServer: true, DHCPServerID: net.ParseIP(serverID).To4(), At: h.now})
}

func TestRogueDHCP(t *testing.T) {
	h := newHarness()
	h.dhcp(router, "192.168.2.1") // first server: trusted
	h.dhcp(router, "192.168.2.1")
	if len(h.found) != 0 {
		t.Fatalf("trusted server alerted: %v", h.events())
	}
	h.dhcp(rogue, "192.168.2.123")
	h.dhcp(rogue, "192.168.2.123") // deduped
	if len(h.found) != 1 || h.found[0].Event != notify.EventRogueDHCP || h.found[0].Trusted[0] != "192.168.2.1" {
		t.Fatalf("want one rogue_dhcp, got %+v", h.found)
	}
	if err := h.g.TrustDHCP("eth0", h.found[0].Key); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(48 * time.Hour)
	h.dhcp(rogue, "192.168.2.123")
	if len(h.found) != 1 {
		t.Fatal("trusted server alerted again")
	}

	// Knowledge survives a restart.
	g2 := New(h.st, func(f Finding) { t.Fatalf("unexpected %+v", f) })
	hw, _ := net.ParseMAC(rogue)
	g2.Observe(passive.Sighting{Iface: "eth0", MAC: hw, Source: passive.SrcDHCP, DHCPServer: true, DHCPServerID: net.IPv4(192, 168, 2, 123).To4()})
}

func TestNonGatewayConflict(t *testing.T) {
	h := newHarness()
	h.arp(phoneA, "192.168.2.50")
	h.now = h.now.Add(10 * time.Second)
	h.arp(phoneB, "192.168.2.50")
	h.now = h.now.Add(10 * time.Second)
	h.arp(phoneA, "192.168.2.50")
	if len(h.found) != 1 || h.found[0].Gateway {
		t.Fatalf("want a plain IP conflict, got %+v", h.found)
	}
}
