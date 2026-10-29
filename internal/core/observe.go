package core

import (
	"net"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/oui"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/router"
	"github.com/playwjj/lanhound/internal/store"
)

// Observe folds one sighting into the device table.
func (r *Registry) Observe(s passive.Sighting) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observe(s, false)
}

// ObserveQuiet is Observe without a new-device alert — for a remote
// probe's first sweep, which is a baseline like LanHound's own.
func (r *Registry) ObserveQuiet(s passive.Sighting) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observe(s, true)
}

func isRouterIface(iface string) bool { return strings.HasPrefix(iface, RouterIfacePrefix) }

// ObserveRouter folds a router's device table in. Devices LanHound sees
// on its own interfaces only take names (and a missing IP) from it —
// their presence stays ARP-based, since router tables keep stale
// entries. Devices only the router knows (another subnet, a guest
// network) are tracked under the interface "router:<label>". quiet
// suppresses new-device alerts, for a source's first sync.
func (r *Registry) ObserveRouter(label string, entries []router.Entry, quiet bool) {
	now := r.o.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	hasWiFi := false
	for _, e := range entries {
		hasWiFi = hasWiFi || e.Wireless != nil
	}
	for _, e := range entries {
		r.observe(passive.Sighting{
			Iface: RouterIfacePrefix + label, MAC: e.MAC, IP: e.IP, Source: passive.SrcRouter,
			Hostname: e.Hostname, HostnameSource: passive.SrcRouter, At: now,
		}, quiet)
		d, ok := r.devices[r.byMAC[e.MAC.String()]]
		if !ok {
			continue
		}
		switch {
		case e.Wireless != nil:
			w := e.Wireless
			changed := d.WiFi == nil || d.WiFi.Band != w.Band || d.WiFi.Router != label
			d.WiFi = &store.WiFi{Band: w.Band, Signal: w.Signal, Radio: w.Radio, Router: label, At: now}
			r.check(r.o.Store.UpdateDevice(d)) // keeps the report's time current
			if changed {
				r.publish(d)
			}
		case hasWiFi && d.WiFi != nil && d.WiFi.Router == label:
			// This router has Wi-Fi and no longer lists the device on it.
			d.WiFi = nil
			r.check(r.o.Store.UpdateDevice(d))
			r.publish(d)
		}
	}
}

// observe is Observe with r.mu held; quiet suppresses a new-device alert.
func (r *Registry) observe(s passive.Sighting, quiet bool) {
	if s.At.IsZero() {
		s.At = r.o.Now()
	}
	if s.HostnameSource == "" {
		s.Hostname = ""
	}
	mac := s.MAC.String()
	id, ok := r.byMAC[mac]
	if !ok {
		r.addDevice(s, mac, quiet)
		return
	}
	d := r.devices[id]
	if s.Source == passive.SrcRouter && !isRouterIface(d.Iface) {
		// A local device: names only.
		changed := r.applyHostname(d, s.Hostname, s.HostnameSource, s.At)
		if d.IP == "" && s.IP != nil {
			d.IP, changed = s.IP.String(), true
		}
		if changed {
			r.check(r.o.Store.UpdateDevice(d))
			r.publish(d)
		}
		return
	}
	if s.Source != passive.SrcRouter && isRouterIface(d.Iface) {
		// Seen first via a router, now on our own wire: ours wins at once.
		r.ifaceSeen[id] = time.Time{}
	}
	changed := false
	prevSeen := d.LastSeen
	if s.At.After(d.LastSeen) {
		d.LastSeen = s.At
		r.dirty[id] = true
	}
	if d.MAC != mac {
		d.MAC, d.Vendor = mac, oui.Lookup(s.MAC)
		changed = true
	}
	if s.Iface != "" && s.Iface != d.Iface && (d.Iface == "" || s.At.Sub(r.ifaceSeen[id]) > ifaceSticky || !d.Online) {
		d.Iface = s.Iface
		changed = true
	}
	if s.Iface == d.Iface {
		r.ifaceSeen[id] = s.At
	}
	if s.IP != nil && s.IP.String() != d.IP {
		if d.IP != "" {
			r.event(id, s.At, store.EventIP, d.IP+" → "+s.IP.String())
		}
		d.IP = s.IP.String()
		changed = true
		r.queueProbe(d)
	}
	if !d.Online {
		d.Online = true
		changed = true
		r.check(r.o.Store.OpenSession(id, s.At))
		r.event(id, s.At, store.EventOnline, d.IP)
		if d.Critical {
			r.criticalAlert(d, true, s.At.Sub(prevSeen))
		}
	}
	if r.applyHostname(d, s.Hostname, s.HostnameSource, s.At) {
		changed = true
	}
	if addIPv6(d, s.IP6) {
		changed = true
	}
	if s.DHCPFingerprint != "" && s.DHCPFingerprint != d.DHCPFP {
		d.DHCPFP = s.DHCPFingerprint
		changed = true
	}
	if s.Model != "" && s.Model != d.Model && (d.Model == "" || s.Source == passive.SrcMDNS) {
		d.Model = s.Model
		changed = true
	}
	if changed {
		delete(r.dirty, id)
		r.check(r.o.Store.UpdateDevice(d))
		r.publish(d)
	}
	if d.Hostname == "" {
		r.queueProbe(d)
	}
}

func (r *Registry) addDevice(s passive.Sighting, mac string, quiet bool) {
	d := &store.Device{
		MAC:       mac,
		Vendor:    oui.Lookup(s.MAC),
		Iface:     s.Iface,
		Online:    true,
		FirstSeen: s.At,
		LastSeen:  s.At,
		Model:     s.Model,
	}
	if s.IP != nil {
		d.IP = s.IP.String()
	}
	d.IPv6 = []string{}
	addIPv6(d, s.IP6)
	d.DHCPFP = s.DHCPFingerprint
	if s.Hostname != "" {
		d.Hostname, d.HostnameSource = s.Hostname, s.HostnameSource
	}
	if err := r.o.Store.InsertDevice(d); err != nil {
		lg().Error("cannot store new device", "mac", mac, "err", err)
		return
	}
	r.devices[d.ID] = d
	r.byMAC[mac] = d.ID
	r.macs[d.ID] = []string{mac}
	r.ifaceSeen[d.ID] = s.At
	r.check(r.o.Store.OpenSession(d.ID, s.At))
	r.event(d.ID, s.At, store.EventNew, d.IP)
	if !r.baseline && !quiet {
		r.pending[d.ID] = s.At.Add(r.o.AlertDelay)
		lg().Info("new device", "mac", mac, "ip", d.IP, "vendor", d.Vendor, "iface", d.Iface)
	}
	r.publish(d)
	if d.Hostname == "" {
		r.queueProbe(d)
	}
}

// addIPv6 records a new IPv6 address (newest first). It reports whether
// the list changed; a known address is not moved, to avoid a write per
// sweep.
func addIPv6(d *store.Device, ip net.IP) bool {
	if ip == nil {
		return false
	}
	a := ip.String()
	for _, have := range d.IPv6 {
		if have == a {
			return false
		}
	}
	list := append([]string{a}, d.IPv6...)
	if len(list) > maxIPv6 {
		list = list[:maxIPv6]
	}
	d.IPv6 = list
	return true
}

// applyHostname adopts name when its source ranks at least as high as
// the current one. It reports whether anything changed.
func (r *Registry) applyHostname(d *store.Device, name, src string, at time.Time) bool {
	if name == "" || name == d.Hostname && src == d.HostnameSource {
		return false
	}
	if d.Hostname != "" && passive.HostnamePriority(src) < passive.HostnamePriority(d.HostnameSource) {
		return false
	}
	if name != d.Hostname {
		r.event(d.ID, at, store.EventHostname, name+" ("+src+")")
		lg().Debug("hostname", "mac", d.MAC, "name", name, "source", src)
	}
	d.Hostname, d.HostnameSource = name, src
	return true
}

func (r *Registry) event(id int64, at time.Time, kind, detail string) {
	r.check(r.o.Store.AddEvent(id, at, kind, detail))
}

func (r *Registry) check(err error) {
	if err != nil {
		lg().Error("database write failed", "err", err)
	}
}

func (r *Registry) queueProbe(d *store.Device) {
	if r.o.Resolve == nil || d.IP == "" || d.Hostname != "" {
		return
	}
	if last, ok := r.lastProbe[d.ID]; ok && r.o.Now().Sub(last) < reprobeAfter {
		return
	}
	r.lastProbe[d.ID] = r.o.Now()
	select {
	case r.probes <- d.ID:
	default:
	}
}
