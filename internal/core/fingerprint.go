package core

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/store"
)

// Randomized-MAC fingerprinting: when a "new" device shows up, is it
// really a device we already know that rotated its MAC? Each piece of
// evidence adds to a score; none is conclusive on its own.
const (
	scoreHostname        = 60 // a distinctive hostname ("Moms-iPhone")
	scoreGenericHostname = 15 // "iPhone", "Galaxy-S24": shared by a family's phones
	scoreModel           = 25 // mDNS/UPnP model ("iPhone15,2")
	scoreDHCP            = 20 // same OS build: option 55 list + vendor class

	// SuggestScore shows a "probably the same as" hint and merge button.
	SuggestScore = 50
	// RecognizeScore with a known candidate suppresses the new-device
	// alert: this is one of yours, wearing a new MAC.
	RecognizeScore = 80

	// overlapSlack: a candidate seen after the newcomer appeared is a
	// different device (a device has one MAC per network at a time).
	overlapSlack = time.Minute
)

// genericHostname matches names many devices share out of the box.
var genericHostname = regexp.MustCompile(`(?i)^(iphone|ipad|ipod|imac|macbook(-?(pro|air))?|android|localhost|unknown|espressif|` +
	`(galaxy|redmi|xiaomi|mi|huawei|honor|oppo|vivo|realme|oneplus|pixel|nova|mate|poco)([-_ ]?[a-z0-9+]{0,8})?)$`)

// Match is a candidate older device for a newcomer.
type Match struct {
	ID      int64    `json:"id"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"` // hostname | model | dhcp
}

// bestMatch finds the older device most likely to be d under another
// MAC. Caller holds r.mu.
func (r *Registry) bestMatch(d *store.Device) (Match, bool) {
	var best Match
	for _, o := range r.devices {
		if o.ID == d.ID || !o.FirstSeen.Before(d.FirstSeen) {
			continue
		}
		if o.LastSeen.After(d.FirstSeen.Add(overlapSlack)) {
			continue // both active at once: two devices
		}
		m := score(d, o)
		if m.Score > best.Score || (m.Score == best.Score && m.Score > 0 && o.FirstSeen.Before(r.devices[best.ID].FirstSeen)) {
			best = m
		}
	}
	return best, best.Score >= SuggestScore
}

func score(d, o *store.Device) Match {
	m := Match{ID: o.ID}
	if d.Hostname != "" && strings.EqualFold(d.Hostname, o.Hostname) {
		if genericHostname.MatchString(d.Hostname) {
			m.Score += scoreGenericHostname
		} else {
			m.Score += scoreHostname
		}
		m.Reasons = append(m.Reasons, "hostname")
	}
	if d.Model != "" && d.Model == o.Model {
		m.Score += scoreModel
		m.Reasons = append(m.Reasons, "model")
	}
	if d.DHCPFP != "" && d.DHCPFP == o.DHCPFP {
		m.Score += scoreDHCP
		m.Reasons = append(m.Reasons, "dhcp")
	}
	sort.Strings(m.Reasons)
	return m
}
