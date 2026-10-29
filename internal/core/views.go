package core

import (
	"net"
	"sort"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/oui"
	"github.com/playwjj/lanhound/internal/store"
)

func (r *Registry) info(d *store.Device) notify.DeviceInfo {
	v := r.view(d)
	info := notify.DeviceInfo{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, Vendor: d.Vendor, Model: d.Model,
		IP: d.IP, MAC: d.MAC, Interface: d.Iface, FirstSeen: d.FirstSeen, Randomized: v.Randomized,
	}
	if o, ok := r.devices[v.SameAs]; ok {
		info.SameAs = firstNonEmpty(o.Name, o.Hostname)
	}
	return info
}

// view builds the API representation. Caller holds r.mu.
func (r *Registry) view(d *store.Device) View { return r.viewWith(d, nil) }

// viewWith is view with a prebuilt feature index, for building many.
func (r *Registry) viewWith(d *store.Device, idx featureIndex) View {
	v := View{Device: *d, MACs: append([]string(nil), r.macs[d.ID]...), Randomized: randomized(d.MAC)}
	if m, ok := r.bestMatch(d, idx); ok {
		v.SameAs, v.SameAsWhy = m.ID, m.Reasons
	}
	v.Link = link(d, r.o.Now())
	return v
}

func (r *Registry) publish(d *store.Device) { r.o.Hub.Publish("device", r.view(d)) }

// randomized reports a locally administered MAC — what phones use for
// per-network MAC randomization. Docker containers' MACs are locally
// administered too, but stable.
func randomized(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0 && !oui.IsDocker(hw)
}

// Devices returns every device, online first, then by IP.
func (r *Registry) Devices() []View {
	r.mu.Lock()
	out := make([]View, 0, len(r.devices))
	idx := r.index()
	for _, d := range r.devices {
		out = append(out, r.viewWith(d, idx))
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return ipKey(out[i].IP) < ipKey(out[j].IP)
	})
	return out
}

func ipKey(s string) string {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return "\xff" + s
	}
	return string(ip)
}

// Device returns one device.
func (r *Registry) Device(id int64) (View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return View{}, ErrNotFound
	}
	return r.view(d), nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
