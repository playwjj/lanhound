// Package web serves the REST API, the live event stream (SSE) and the
// embedded Vue front end.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/scanner"
)

//go:embed all:dist
var dist embed.FS

// Scanner is the part of the discovery engine the web layer needs.
type Scanner interface {
	Status() []scanner.Status
	Skipped() []string
	Sweep()
}

// Security is the part of the security guard the web layer needs.
type Security interface {
	Gateways() map[string][]string
	TrustDHCP(iface, key string) error
}

// Server is the HTTP front of LanHound.
type Server struct {
	Registry *core.Registry
	Settings *core.Settings
	Hub      *core.Hub
	Scanner  Scanner
	Security Security
	Version  string
	Interval time.Duration
	// Password enables HTTP basic auth (any username) when non-empty.
	Password string

	started time.Time
}

// Status is the dashboard header payload.
type Status struct {
	Version      string              `json:"version"`
	StartedAt    time.Time           `json:"startedAt"`
	Baseline     bool                `json:"baseline"`
	ScanInterval int                 `json:"scanInterval"` // seconds
	Interfaces   []scanner.Status    `json:"interfaces"`
	Skipped      []string            `json:"skipped"`
	Notify       bool                `json:"notify"` // a channel is configured
	Alerts       core.AlertStatus    `json:"alerts"`
	Gateways     map[string][]string `json:"gateways"` // interface → default gateway(s)
}

// Status builds the current status payload.
func (s *Server) Status() Status {
	skipped := s.Scanner.Skipped()
	if skipped == nil {
		skipped = []string{}
	}
	gateways := map[string][]string{}
	if s.Security != nil {
		gateways = s.Security.Gateways()
	}
	return Status{
		Gateways:     gateways,
		Version:      s.Version,
		StartedAt:    s.started,
		Baseline:     s.Registry.Baseline(),
		ScanInterval: int(s.Interval / time.Second),
		Interfaces:   s.Scanner.Status(),
		Skipped:      skipped,
		Notify:       s.Settings.Get().Configured(),
		Alerts:       s.Registry.AlertStatus(),
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	s.started = time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Status()) })
	mux.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Registry.Devices()) })
	mux.HandleFunc("GET /api/devices.csv", s.exportCSV)
	mux.HandleFunc("GET /api/devices/{id}", s.device)
	mux.HandleFunc("PATCH /api/devices/{id}", s.patchDevice)
	mux.HandleFunc("DELETE /api/devices/{id}", s.deleteDevice)
	mux.HandleFunc("POST /api/devices/{id}/merge", s.mergeDevice)
	mux.HandleFunc("GET /api/devices/{id}/history", s.history)
	mux.HandleFunc("POST /api/known-all", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Registry.MarkAllKnown(); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		s.Scanner.Sweep()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/alerts", s.alerts)
	mux.HandleFunc("POST /api/alerts/{id}/trust", s.trustAlert)
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Settings.Public()) })
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("POST /api/settings/test", s.testSettings)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "not found", http.StatusNotFound) })
	mux.Handle("/", static())
	return s.guard(mux)
}

// guard applies optional basic auth, and requires a custom header on
// state-changing requests so another website cannot drive the API
// from a visitor's browser (custom headers force a CORS preflight,
// which we never approve).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Password != "" {
			_, pass, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(s.Password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="LanHound"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			if r.Header.Get("X-LanHound") == "" {
				http.Error(w, "missing X-LanHound header", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.Registry.Device(id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, v)
}

// exportCSV downloads the device table. The UTF-8 BOM makes Excel read
// non-ASCII names correctly.
func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="lanhound-devices-`+time.Now().Format("20060102")+`.csv"`)
	_, _ = w.Write([]byte("\ufeff"))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"name", "hostname", "ip", "mac", "all_macs", "randomized", "vendor", "model", "interface", "known", "online", "first_seen", "last_seen", "note"})
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339)
	}
	for _, d := range s.Registry.Devices() {
		_ = cw.Write([]string{
			csvSafe(d.Name), csvSafe(d.Hostname), d.IP, d.MAC, strings.Join(d.MACs, " "), strconv.FormatBool(d.Randomized),
			csvSafe(d.Vendor), csvSafe(d.Model), d.Iface, strconv.FormatBool(d.Known), strconv.FormatBool(d.Online),
			ts(d.FirstSeen), ts(d.LastSeen), csvSafe(d.Note),
		})
	}
	cw.Flush()
}

// csvSafe defuses spreadsheet formula injection: hostnames are chosen
// by whatever device joins the network.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) patchDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var p core.Patch
	if !readJSON(w, r, &p) {
		return
	}
	v, err := s.Registry.Update(id, p)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.Registry.Delete(id); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) mergeDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Into int64 `json:"into"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	v, err := s.Registry.Merge(id, body.Into)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 90 {
		days = 7
	}
	h, err := s.Registry.History(id, time.Now().AddDate(0, 0, -days))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, h)
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	list, err := s.Registry.Alerts(limit)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, list)
}

// trustAlert marks the DHCP server of a rogue_dhcp alert as expected.
func (s *Server) trustAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	_, m, err := s.Registry.Alert(id)
	if err != nil {
		fail(w, err)
		return
	}
	if m.Event != notify.EventRogueDHCP || m.Key == "" || s.Security == nil {
		http.Error(w, "only DHCP-server alerts can be trusted", http.StatusBadRequest)
		return
	}
	if err := s.Security.TrustDHCP(m.Interface, m.Key); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var n notify.Settings
	if !readJSON(w, r, &n) {
		return
	}
	if _, err := s.Settings.Put(n); err != nil {
		fail(w, err)
		return
	}
	s.Hub.Publish("status", s.Status())
	writeJSON(w, s.Settings.Public())
}

func (s *Server) testSettings(w http.ResponseWriter, r *http.Request) {
	var n notify.Settings
	if !readJSON(w, r, &n) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Registry.SendTest(ctx, s.Settings.Resolve(n)); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// events streams changes as Server-Sent Events. The first message is a
// full snapshot, so a reconnecting client never misses a change.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, cancel := s.Hub.Subscribe()
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // let reverse proxies stream
	snap, _ := json.Marshal(core.Message{Type: "snapshot", Data: map[string]any{
		"devices": s.Registry.Devices(),
		"status":  s.Status(),
	}})
	writeEvent(w, snap)
	flusher.Flush()

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return // fell behind; the browser reconnects and resyncs
			}
			writeEvent(w, msg)
			flusher.Flush()
		case <-keepalive.C:
			_, _ = w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, data []byte) {
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n\n"))
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	if errors.Is(err, core.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	log.Printf("web: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// static serves the embedded front end, falling back to index.html for
// client-side routes.
func static() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(sub, p); err != nil {
				r.URL.Path = "/"
			}
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
