// Package security watches the sightings stream for signs of trouble on
// the segment: ARP spoofing and IP conflicts, ARP floods, a gateway that
// suddenly answers from another MAC, and DHCP servers that should not be
// there.
//
// LanHound only detects and reports. It never sends countermeasures —
// no corrective ARP, no deauth, no DHCP starvation. Enforcement belongs
// to the router.
//
// What a host on a switched network can see is limited: unicast ARP
// replies aimed at two other machines never reach it. Detection works
// when an attacker poisons broadcast-wide (the default of common tools)
// or poisons this host, and gateway/DHCP checks work regardless.
package security

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/logx"
	"github.com/playwjj/lanhound/internal/netutil"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/passive"
)

// Tuning. Conservative on purpose: an alert that cries wolf gets ignored.
const (
	// ClaimWindow is how long an ARP claim of an IP stays "current". It
	// spans more than one sweep so the genuine owner, which answers
	// every sweep, is always in view.
	ClaimWindow = 10 * time.Minute
	// FloodWindow / FloodThreshold: unsolicited ARP packets from one MAC.
	FloodWindow    = 10 * time.Second
	FloodThreshold = 20

	repeatConflict = time.Hour
	repeatFlood    = 30 * time.Minute
	repeatDHCP     = 24 * time.Hour
	gatewayRefresh = 30 * time.Second
)

// Finding is something worth an alert. Messages carry raw MACs; the
// caller turns them into named devices.
type Finding struct {
	Event     string
	Interface string
	IP        net.IP
	Gateway   bool
	MACs      []net.HardwareAddr
	Count     int
	Seconds   int64
	Trusted   []string // rogue DHCP: the servers already known
	Key       string   // rogue DHCP: pass to TrustDHCP
}

// Store persists what the guard has learned (gateway MACs, trusted DHCP
// servers) across restarts.
type Store interface {
	Setting(key string) (string, error)
	SetSetting(key, value string) error
}

type claim struct{ first, last time.Time }

type flood struct {
	start time.Time
	count int
}

// Guard is the detector. Observe is safe for concurrent use.
type Guard struct {
	store Store
	emit  func(Finding)
	now   func() time.Time

	mu        sync.Mutex
	claims    map[string]map[string]*claim // iface|ip → MAC → claim
	floods    map[string]*flood            // MAC → current window
	gateways  map[string][]net.IP          // iface → default gateways
	extra     func() map[string][]net.IP   // remote probes' gateways
	lastAlert map[string]time.Time         // dedupe key → when
}

// New returns a Guard that reports findings to emit.
func New(store Store, emit func(Finding)) *Guard {
	return &Guard{
		store:     store,
		emit:      emit,
		now:       time.Now,
		claims:    map[string]map[string]*claim{},
		floods:    map[string]*flood{},
		gateways:  map[string][]net.IP{},
		lastAlert: map[string]time.Time{},
	}
}

// Run keeps the gateway list current until ctx is done.
func (g *Guard) Run(ctx context.Context) {
	g.SetGateways(netutil.Gateways())
	t := time.NewTicker(gatewayRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.SetGateways(netutil.Gateways())
		}
	}
}

// SetGateways replaces the per-interface default gateways.
func (g *Guard) SetGateways(gw map[string][]net.IP) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if gw == nil {
		gw = map[string][]net.IP{}
	}
	g.gateways = gw
}

// Gateways returns the current default gateways, remote probes'
// included (for the UI).
func (g *Guard) Gateways() map[string][]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string][]string{}
	all := map[string][]net.IP{}
	if g.extra != nil {
		for k, v := range g.extra() {
			all[k] = v
		}
	}
	for k, v := range g.gateways {
		all[k] = v
	}
	for iface, ips := range all {
		for _, ip := range ips {
			out[iface] = append(out[iface], ip.String())
		}
	}
	return out
}

// Observe inspects one sighting.
func (g *Guard) Observe(s passive.Sighting) {
	if s.At.IsZero() {
		s.At = g.now()
	}
	var out []Finding
	g.mu.Lock()
	switch {
	case s.DHCPServer:
		out = g.dhcpServer(s)
	case s.Source == passive.SrcARP || s.Source == passive.SrcARPReply:
		out = g.arp(s)
	}
	g.mu.Unlock()
	for _, f := range out {
		g.emit(f)
	}
}

// due reports whether an alert under key may fire again, and records it.
// Caller holds g.mu.
func (g *Guard) due(key string, every time.Duration, now time.Time) bool {
	if last, ok := g.lastAlert[key]; ok && now.Sub(last) < every {
		return false
	}
	g.lastAlert[key] = now
	return true
}

func (g *Guard) arp(s passive.Sighting) []Finding {
	var out []Finding
	mac := s.MAC.String()

	// Floods: unsolicited announcements and replies. Requests do not
	// count — routers legitimately ARP-scan whole subnets.
	if s.Gratuitous || s.Source == passive.SrcARPReply {
		f := g.floods[mac]
		if f == nil || s.At.Sub(f.start) > FloodWindow {
			f = &flood{start: s.At}
			g.floods[mac] = f
		}
		f.count++
		if f.count == FloodThreshold && g.due("flood|"+mac, repeatFlood, s.At) {
			out = append(out, Finding{
				Event: notify.EventARPFlood, Interface: s.Iface, MACs: []net.HardwareAddr{s.MAC},
				Count: f.count, Seconds: int64(FloodWindow / time.Second),
			})
		}
	}
	if s.IP == nil {
		return out
	}

	// Conflicts: two MACs whose claims on one IP overlap in time. A phone
	// that rejoins with a new random MAC and gets its old IP back does
	// not overlap — the old MAC went quiet first.
	key := s.Iface + "|" + s.IP.String()
	byMAC := g.claims[key]
	if byMAC == nil {
		byMAC = map[string]*claim{}
		g.claims[key] = byMAC
	}
	for m, c := range byMAC {
		if s.At.Sub(c.last) > ClaimWindow {
			delete(byMAC, m)
		}
	}
	me := byMAC[mac]
	if me == nil {
		me = &claim{first: s.At}
		byMAC[mac] = me
	}
	me.last = s.At
	isGateway := g.isGateway(s.Iface, s.IP)
	for m, other := range byMAC {
		if m == mac || other.last.Before(me.first) {
			continue
		}
		// Established claimant first.
		macs := []net.HardwareAddr{mustMAC(m), s.MAC}
		if me.first.Before(other.first) {
			macs[0], macs[1] = macs[1], macs[0]
		}
		pair := []string{m, mac}
		sort.Strings(pair)
		if g.due("conflict|"+key+"|"+strings.Join(pair, ","), repeatConflict, s.At) {
			out = append(out, Finding{Event: notify.EventARPConflict, Interface: s.Iface, IP: s.IP, Gateway: isGateway, MACs: macs})
		}
	}

	if isGateway {
		out = append(out, g.gatewayMAC(s, byMAC)...)
	}
	return out
}

func (g *Guard) isGateway(iface string, ip net.IP) bool {
	list := g.gateways[iface]
	if g.extra != nil && len(list) == 0 {
		list = g.extra()[iface]
	}
	for _, gw := range list {
		if gw.Equal(ip) {
			return true
		}
	}
	return false
}

// SetExtraGateways adds a source of gateways for interfaces this host
// does not own (remote probes, "<probe>/<iface>").
func (g *Guard) SetExtraGateways(f func() map[string][]net.IP) {
	g.mu.Lock()
	g.extra = f
	g.mu.Unlock()
}

// gatewayMAC remembers which MAC answers for the gateway and reports a
// change once the old MAC has gone quiet. While both still claim the
// address it is a conflict, already reported above.
func (g *Guard) gatewayMAC(s passive.Sighting, claims map[string]*claim) []Finding {
	key := "security.gateway." + s.Iface + "." + s.IP.String()
	stored, err := g.store.Setting(key)
	if err != nil {
		lg().Error("cannot persist security state", "err", err)
		return nil
	}
	mac := s.MAC.String()
	if stored == mac {
		return nil
	}
	if stored != "" {
		if _, stillThere := claims[stored]; stillThere {
			return nil
		}
	}
	if err := g.store.SetSetting(key, mac); err != nil {
		lg().Error("cannot persist security state", "err", err)
	}
	if stored == "" {
		return nil // first time we learn it
	}
	return []Finding{{
		Event: notify.EventGatewayChanged, Interface: s.Iface, IP: s.IP, Gateway: true,
		MACs: []net.HardwareAddr{mustMAC(stored), s.MAC},
	}}
}

// dhcpKey identifies a DHCP server by its server identifier and MAC.
func dhcpKey(s passive.Sighting) string {
	id := s.DHCPServerID
	if id == nil {
		id = s.IP
	}
	idStr := "?"
	if id != nil {
		idStr = id.String()
	}
	return idStr + "/" + s.MAC.String()
}

// dhcpServer trusts the first DHCP server seen on an interface and
// reports any other.
func (g *Guard) dhcpServer(s passive.Sighting) []Finding {
	key := dhcpKey(s)
	trusted, err := g.trusted(s.Iface)
	if err != nil {
		lg().Error("cannot persist security state", "err", err)
		return nil
	}
	if len(trusted) == 0 {
		lg().Info("trusting DHCP server (first seen)", "server", key, "iface", s.Iface)
		if err := g.saveTrusted(s.Iface, []string{key}); err != nil {
			lg().Error("cannot persist security state", "err", err)
		}
		return nil
	}
	for _, t := range trusted {
		if t == key {
			return nil
		}
	}
	if !g.due("dhcp|"+s.Iface+"|"+key, repeatDHCP, s.At) {
		return nil
	}
	ip := s.DHCPServerID
	if ip == nil {
		ip = s.IP
	}
	names := make([]string, len(trusted))
	for i, t := range trusted {
		names[i], _, _ = strings.Cut(t, "/")
	}
	return []Finding{{
		Event: notify.EventRogueDHCP, Interface: s.Iface, IP: ip,
		MACs: []net.HardwareAddr{s.MAC}, Trusted: names, Key: key,
	}}
}

func (g *Guard) trusted(iface string) ([]string, error) {
	raw, err := g.store.Setting("security.dhcp." + iface)
	if err != nil || raw == "" {
		return nil, err
	}
	var list []string
	err = json.Unmarshal([]byte(raw), &list)
	return list, err
}

func (g *Guard) saveTrusted(iface string, list []string) error {
	b, _ := json.Marshal(list)
	return g.store.SetSetting("security.dhcp."+iface, string(b))
}

// TrustDHCP marks a DHCP server (the Key of a rogue_dhcp finding) as
// expected on iface.
func (g *Guard) TrustDHCP(iface, key string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	list, err := g.trusted(iface)
	if err != nil {
		return err
	}
	for _, t := range list {
		if t == key {
			return nil
		}
	}
	return g.saveTrusted(iface, append(list, key))
}

func mustMAC(s string) net.HardwareAddr {
	hw, _ := net.ParseMAC(s)
	return hw
}

func lg() *slog.Logger { return logx.L("security") }
