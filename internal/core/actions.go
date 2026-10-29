package core

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/store"
)

// Update applies a user edit.
func (r *Registry) Update(id int64, p Patch) (View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return View{}, ErrNotFound
	}
	if p.Name != nil {
		d.Name = limit(strings.TrimSpace(*p.Name), 64)
	}
	if p.Note != nil {
		d.Note = limit(strings.TrimSpace(*p.Note), 500)
	}
	if p.Known != nil {
		d.Known = *p.Known
		if d.Known {
			delete(r.pending, id)
		}
	}
	if p.Critical != nil {
		d.Critical = *p.Critical
	}
	if err := r.o.Store.UpdateDevice(d); err != nil {
		return View{}, err
	}
	r.publish(d)
	return r.view(d), nil
}

func limit(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// MarkAllKnown acknowledges every device.
func (r *Registry) MarkAllKnown() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.o.Store.MarkAllKnown(); err != nil {
		return err
	}
	r.pending = map[int64]time.Time{}
	for _, d := range r.devices {
		if !d.Known {
			d.Known = true
			r.publish(d)
		}
	}
	return nil
}

// Merge folds device src into dst: its MACs, history and, where dst has
// none, its name and note. Use it when a phone's randomized MAC shows up
// as a new device.
func (r *Registry) Merge(src, dst int64) (View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok1 := r.devices[src]
	d, ok2 := r.devices[dst]
	if !ok1 || !ok2 || src == dst {
		return View{}, ErrNotFound
	}
	m := *d
	if m.Name == "" {
		m.Name = s.Name
	}
	if m.Note == "" {
		m.Note = s.Note
	}
	m.Known = d.Known || s.Known
	m.Critical = d.Critical || s.Critical
	if s.FirstSeen.Before(m.FirstSeen) {
		m.FirstSeen = s.FirstSeen
	}
	if s.LastSeen.After(d.LastSeen) {
		m.LastSeen, m.MAC, m.Vendor, m.IP, m.Iface = s.LastSeen, s.MAC, s.Vendor, s.IP, s.Iface
		if s.DHCPFP != "" {
			m.DHCPFP = s.DHCPFP
		}
	}
	m.Online = d.Online || s.Online
	if s.Hostname != "" && (m.Hostname == "" || passive.HostnamePriority(s.HostnameSource) > passive.HostnamePriority(m.HostnameSource)) {
		m.Hostname, m.HostnameSource = s.Hostname, s.HostnameSource
	}
	if m.Model == "" {
		m.Model = s.Model
	}
	if s.WiFi != nil && (m.WiFi == nil || s.WiFi.At.After(m.WiFi.At)) {
		m.WiFi = s.WiFi
	}
	for i := len(s.IPv6) - 1; i >= 0; i-- {
		addIPv6(&m, net.ParseIP(s.IPv6[i]))
	}
	if err := r.o.Store.Merge(src, &m); err != nil {
		return View{}, err
	}
	*d = m
	for _, mac := range r.macs[src] {
		r.byMAC[mac] = dst
	}
	r.macs[dst] = append(r.macs[dst], r.macs[src]...)
	delete(r.macs, src)
	delete(r.devices, src)
	delete(r.pending, src)
	delete(r.dirty, src)
	r.event(dst, r.o.Now(), store.EventMerged, strings.Join(r.macs[dst], ", "))
	r.o.Hub.Publish("remove", map[string]int64{"id": src})
	r.publish(d)
	// Other devices' merge hints may point at src.
	for _, o := range r.devices {
		if o.ID != dst && strings.EqualFold(o.Hostname, d.Hostname) && o.Hostname != "" {
			r.publish(o)
		}
	}
	return r.view(d), nil
}

// Delete forgets a device and its history. If it shows up again it is
// treated as new.
func (r *Registry) Delete(id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.devices[id]; !ok {
		return ErrNotFound
	}
	if err := r.o.Store.DeleteDevice(id); err != nil {
		return err
	}
	for _, mac := range r.macs[id] {
		delete(r.byMAC, mac)
	}
	for _, m := range []map[int64]time.Time{r.ifaceSeen, r.lastProbe, r.pending} {
		delete(m, id)
	}
	delete(r.macs, id)
	delete(r.devices, id)
	delete(r.dirty, id)
	r.o.Hub.Publish("remove", map[string]int64{"id": id})
	return nil
}

// History returns sessions since `since` and the latest events.
func (r *Registry) History(id int64, since time.Time) (History, error) {
	r.mu.Lock()
	_, ok := r.devices[id]
	r.mu.Unlock()
	if !ok {
		return History{}, ErrNotFound
	}
	var h History
	var err error
	if h.Sessions, err = r.o.Store.Sessions(id, since); err != nil {
		return h, err
	}
	h.Events, err = r.o.Store.Events(id, 100)
	return h, err
}

// SendTest sends a test message with the given settings.
func (r *Registry) SendTest(ctx context.Context, s notify.Settings) error {
	return r.o.Send(ctx, s, notify.Message{Event: notify.EventTest})
}
