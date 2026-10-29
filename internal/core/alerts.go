package core

import (
	"context"
	"encoding/json"
	"time"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/oui"
	"github.com/playwjj/lanhound/internal/security"
	"github.com/playwjj/lanhound/internal/store"
)

// retryDelays spaces out redelivery of an alert whose channel failed —
// a flaky DNS server or a router reboot should not swallow an alert.
var retryDelays = []time.Duration{0, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}

// AlertView is a logged alert plus its wording in every UI language,
// so the UI never re-implements alert texts.
type AlertView struct {
	store.Alert
	Text map[string]notify.Parts `json:"text"`
}

// Languages the UI offers.
var uiLanguages = []string{"en", "zh"}

func alertView(a store.Alert) AlertView {
	v := AlertView{Alert: a, Text: map[string]notify.Parts{}}
	var m notify.Message
	if json.Unmarshal(a.Data, &m) == nil {
		plain := func(s string) string { return s }
		for _, l := range uiLanguages {
			v.Text[l] = notify.Describe(m, l, plain)
		}
	}
	return v
}

// raise records an alert in the log, shows it in the UI and delivers it
// to the configured channels. It never takes r.mu itself, so callers may
// hold it.
func (r *Registry) raise(m notify.Message, deviceID int64) {
	data, _ := json.Marshal(m)
	a := &store.Alert{At: r.o.Now(), Kind: m.Event, DeviceID: deviceID, Data: data}
	if err := r.o.Store.AddAlert(a); err != nil {
		lg().Error("cannot record alert", "err", err)
	}
	r.o.Hub.Publish("alert", alertView(*a))
	lg().Info("alert", "event", m.Event, "ip", m.IP, "devices", len(m.Devices))
	go r.deliver(m)
}

func (r *Registry) deliver(m notify.Message) {
	ctx := r.runCtx()
	for i, delay := range retryDelays {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		// Re-read settings each attempt: the user may have fixed them.
		set := r.o.Settings.Get()
		if !set.Configured() || !set.Wants(m.Event) {
			return
		}
		sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := r.o.Send(sendCtx, set, m)
		cancel()
		r.mu.Lock()
		if err != nil {
			r.alertState.LastError = err.Error()
		} else {
			r.alertState.LastSent, r.alertState.LastError = r.o.Now(), ""
		}
		st := r.alertState
		r.mu.Unlock()
		r.o.Hub.Publish("alerts", st)
		if err == nil {
			return
		}
		if i < len(retryDelays)-1 {
			lg().Warn("alert delivery failed, will retry", "event", m.Event, "retry_in", retryDelays[i+1].String(), "err", err)
		} else {
			lg().Error("alert delivery failed, giving up", "event", m.Event, "err", err)
		}
	}
}

func (r *Registry) runCtx() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

// RaiseFinding turns a security finding into an alert, naming the MACs
// involved where LanHound knows them.
func (r *Registry) RaiseFinding(f security.Finding) {
	r.mu.Lock()
	m := notify.Message{Event: f.Event, Interface: f.Interface, Gateway: f.Gateway, Count: f.Count, Seconds: f.Seconds, Trusted: f.Trusted, Key: f.Key}
	if f.IP != nil {
		m.IP = f.IP.String()
	}
	var deviceID int64
	known := 0
	for _, mac := range f.MACs {
		var info notify.DeviceInfo
		if id, ok := r.byMAC[mac.String()]; ok {
			info = r.info(r.devices[id])
			info.MAC = mac.String() // the MAC involved, not necessarily the device's latest
			deviceID = id
			known++
		} else {
			info = notify.DeviceInfo{MAC: mac.String(), Vendor: oui.Lookup(mac), Interface: f.Interface, Randomized: randomized(mac.String())}
		}
		if f.IP != nil && f.Event != notify.EventRogueDHCP {
			info.IP = m.IP // the address being claimed
		}
		m.Devices = append(m.Devices, info)
	}
	if known != 1 {
		deviceID = 0
	}
	r.mu.Unlock()
	r.raise(m, deviceID)
}

// Alerts returns the most recent alerts, newest first, with their wording.
func (r *Registry) Alerts(limit int) ([]AlertView, error) {
	list, err := r.o.Store.Alerts(limit)
	if err != nil {
		return nil, err
	}
	out := make([]AlertView, len(list))
	for i, a := range list {
		out[i] = alertView(a)
	}
	return out, nil
}

// Alert returns one logged alert and its decoded message.
func (r *Registry) Alert(id int64) (store.Alert, notify.Message, error) {
	a, err := r.o.Store.Alert(id)
	if err != nil {
		return a, notify.Message{}, ErrNotFound
	}
	var m notify.Message
	err = json.Unmarshal(a.Data, &m)
	return a, m, err
}

// criticalAlert reports a critical device going offline or coming back.
// Caller holds r.mu.
func (r *Registry) criticalAlert(d *store.Device, online bool, away time.Duration) {
	m := notify.Message{Event: notify.EventDeviceOffline, Interface: d.Iface, Devices: []notify.DeviceInfo{r.info(d)}}
	if online {
		m.Event, m.Seconds = notify.EventDeviceOnline, int64(away/time.Second)
	}
	r.raise(m, d.ID)
}
