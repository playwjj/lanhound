package core

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/scanner"
	"github.com/playwjj/lanhound/internal/store"
)

// Remote probes: a `lanhound agent` on another segment (a VLAN, the guest
// network) scans locally and uploads its sightings here. Their
// interfaces show up as "<probe>/<iface>".

const (
	probesKey = "probes"
	// ProbeStale is how long a probe may stay silent before it is shown
	// offline and its devices stop aging out.
	ProbeStale = 2 * time.Minute
)

// ErrBadToken is returned for an unknown or wrong probe token.
var ErrBadToken = errors.New("invalid probe token")

type probeRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	TokenHash string `json:"tokenHash"`
}

// ProbeStatus is what the UI shows per probe.
type ProbeStatus struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Online     bool             `json:"online"`
	LastSeen   time.Time        `json:"lastSeen"`
	Version    string           `json:"version,omitempty"`
	Interfaces []scanner.Status `json:"interfaces"`
}

// WireSighting is a sighting as an agent uploads it.
type WireSighting struct {
	Iface          string    `json:"iface"`
	MAC            string    `json:"mac"`
	IP             string    `json:"ip,omitempty"`
	IP6            string    `json:"ip6,omitempty"`
	Source         string    `json:"source"`
	Hostname       string    `json:"hostname,omitempty"`
	HostnameSource string    `json:"hostnameSource,omitempty"`
	Model          string    `json:"model,omitempty"`
	Gratuitous     bool      `json:"gratuitous,omitempty"`
	DHCPServer     bool      `json:"dhcpServer,omitempty"`
	DHCPServerID   string    `json:"dhcpServerId,omitempty"`
	DHCPFP         string    `json:"dhcpFingerprint,omitempty"`
	At             time.Time `json:"at"`
}

// ToWire converts a sighting for upload.
func ToWire(s passive.Sighting) WireSighting {
	w := WireSighting{Iface: s.Iface, MAC: s.MAC.String(), Source: s.Source, Hostname: s.Hostname, HostnameSource: s.HostnameSource,
		Model: s.Model, Gratuitous: s.Gratuitous, DHCPServer: s.DHCPServer, DHCPFP: s.DHCPFingerprint, At: s.At}
	if s.IP != nil {
		w.IP = s.IP.String()
	}
	if s.IP6 != nil {
		w.IP6 = s.IP6.String()
	}
	if s.DHCPServerID != nil {
		w.DHCPServerID = s.DHCPServerID.String()
	}
	return w
}

func (w WireSighting) sighting(prefix string, now time.Time) (passive.Sighting, bool) {
	mac, err := net.ParseMAC(w.MAC)
	if err != nil || len(mac) != 6 {
		return passive.Sighting{}, false
	}
	s := passive.Sighting{Iface: prefix + w.Iface, MAC: mac, Source: w.Source, Hostname: w.Hostname, HostnameSource: w.HostnameSource,
		Model: w.Model, Gratuitous: w.Gratuitous, DHCPServer: w.DHCPServer, DHCPFingerprint: w.DHCPFP, At: w.At}
	s.IP = net.ParseIP(w.IP).To4()
	if ip := net.ParseIP(w.IP6); ip != nil && ip.To4() == nil {
		s.IP6 = ip
	}
	s.DHCPServerID = net.ParseIP(w.DHCPServerID).To4()
	// Trust the agent's clock only within reason.
	if s.At.IsZero() || s.At.After(now.Add(time.Minute)) || s.At.Before(now.Add(-time.Hour)) {
		s.At = now
	}
	return s, true
}

// Upload is one agent report.
type Upload struct {
	Version    string              `json:"version"`
	Interfaces []scanner.Status    `json:"interfaces"`
	Gateways   map[string][]string `json:"gateways"`
	Sightings  []WireSighting      `json:"sightings"`
}

type probeState struct {
	synced     bool // finished its first sweep: alerts from now on
	lastSeen   time.Time
	version    string
	interfaces []scanner.Status
	gateways   map[string][]net.IP
}

// Probes manages remote agents.
type Probes struct {
	store   *store.Store
	observe func(s passive.Sighting, quiet bool)
	now     func() time.Time

	mu      sync.Mutex
	records []probeRecord
	state   map[string]*probeState // by probe ID
}

// NewProbes loads the registered probes; observe receives their
// sightings (registry and security guard). quiet is set until a probe's
// first sweep has finished: that sweep is a silent baseline.
func NewProbes(st *store.Store, observe func(s passive.Sighting, quiet bool)) (*Probes, error) {
	p := &Probes{store: st, observe: observe, now: time.Now, state: map[string]*probeState{}}
	raw, err := st.Setting(probesKey)
	if err != nil {
		return nil, err
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &p.records); err != nil {
			return nil, err
		}
	}
	return p, nil
}

var probeNameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// Add registers a probe and returns its token — shown once, stored only
// as a hash.
func (p *Probes) Add(name string) (ProbeStatus, string, error) {
	name = strings.Trim(probeNameRe.ReplaceAllString(strings.TrimSpace(name), "-"), "-")
	if name == "" {
		return ProbeStatus{}, "", errors.New("probe name is required (letters, digits, . _ -)")
	}
	if len(name) > 32 {
		name = name[:32]
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.records {
		if strings.EqualFold(r.Name, name) {
			return ProbeStatus{}, "", errors.New("a probe with this name exists")
		}
	}
	tok := make([]byte, 24)
	id := make([]byte, 6)
	_, _ = rand.Read(tok)
	_, _ = rand.Read(id)
	token := "lhp_" + hex.EncodeToString(tok)
	r := probeRecord{ID: hex.EncodeToString(id), Name: name, TokenHash: hashToken(token)}
	if err := p.save(append(append([]probeRecord(nil), p.records...), r)); err != nil {
		return ProbeStatus{}, "", err
	}
	return ProbeStatus{ID: r.ID, Name: r.Name, Interfaces: []scanner.Status{}}, token, nil
}

// Remove deletes a probe; its token stops working at once.
func (p *Probes) Remove(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var keep []probeRecord
	for _, r := range p.records {
		if r.ID != id {
			keep = append(keep, r)
		}
	}
	if len(keep) == len(p.records) {
		return ErrNotFound
	}
	delete(p.state, id)
	return p.save(keep)
}

// save persists records. Caller holds p.mu.
func (p *Probes) save(records []probeRecord) error {
	if records == nil {
		records = []probeRecord{}
	}
	b, _ := json.Marshal(records)
	if err := p.store.SetSetting(probesKey, string(b)); err != nil {
		return err
	}
	p.records = records
	return nil
}

// Ingest accepts an upload authenticated by token.
func (p *Probes) Ingest(token string, u Upload) error {
	h := hashToken(token)
	p.mu.Lock()
	var rec *probeRecord
	for i := range p.records {
		if subtle.ConstantTimeCompare([]byte(p.records[i].TokenHash), []byte(h)) == 1 {
			rec = &p.records[i]
		}
	}
	if rec == nil {
		p.mu.Unlock()
		return ErrBadToken
	}
	now := p.now()
	prefix := rec.Name + "/"
	st := p.state[rec.ID]
	if st == nil {
		synced, _ := p.store.Setting("probe.synced." + rec.ID)
		st = &probeState{synced: synced != ""}
		p.state[rec.ID] = st
	}
	quiet := !st.synced
	if quiet {
		for _, s := range u.Interfaces {
			if !s.LastSweep.IsZero() {
				// First sweep done: this upload still carries its tail,
				// later ones alert.
				st.synced = true
				_ = p.store.SetSetting("probe.synced."+rec.ID, "1")
				log.Printf("probe %s: first sweep done, alerting on new devices from now on", rec.Name)
				break
			}
		}
	}
	st.lastSeen, st.version = now, u.Version
	st.interfaces = make([]scanner.Status, 0, len(u.Interfaces))
	for _, s := range u.Interfaces {
		s.Interface = prefix + s.Interface
		st.interfaces = append(st.interfaces, s)
	}
	st.gateways = map[string][]net.IP{}
	for iface, ips := range u.Gateways {
		for _, a := range ips {
			if ip := net.ParseIP(a).To4(); ip != nil {
				st.gateways[prefix+iface] = append(st.gateways[prefix+iface], ip)
			}
		}
	}
	p.mu.Unlock()

	for _, w := range u.Sightings {
		if s, ok := w.sighting(prefix, now); ok {
			p.observe(s, quiet)
		}
	}
	return nil
}

// Status lists probes, newest-seen first.
func (p *Probes) Status() []ProbeStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	out := make([]ProbeStatus, 0, len(p.records))
	for _, r := range p.records {
		ps := ProbeStatus{ID: r.ID, Name: r.Name, Interfaces: []scanner.Status{}}
		if st := p.state[r.ID]; st != nil {
			ps.LastSeen, ps.Version = st.lastSeen, st.version
			ps.Online = now.Sub(st.lastSeen) < ProbeStale
			ps.Interfaces = append(ps.Interfaces, st.interfaces...)
		}
		out = append(out, ps)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Interfaces returns every online probe's interfaces, for the dashboard.
func (p *Probes) Interfaces() []scanner.Status {
	var out []scanner.Status
	for _, ps := range p.Status() {
		for _, s := range ps.Interfaces {
			if !ps.Online {
				s.Error = "probe offline"
			}
			out = append(out, s)
		}
	}
	return out
}

// Gateways returns probes' default gateways by prefixed interface.
func (p *Probes) Gateways() map[string][]net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string][]net.IP{}
	for _, st := range p.state {
		for k, v := range st.gateways {
			out[k] = v
		}
	}
	return out
}

// Stale reports whether iface belongs to a probe that stopped reporting:
// its devices should not be marked offline just because the probe is
// gone.
func (p *Probes) Stale(iface string) bool {
	name, _, ok := strings.Cut(iface, "/")
	if !ok {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.records {
		if r.Name == name {
			st := p.state[r.ID]
			return st == nil || p.now().Sub(st.lastSeen) >= ProbeStale
		}
	}
	return false
}
