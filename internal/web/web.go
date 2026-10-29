// Package web serves the REST API, the live event stream (SSE) and the
// embedded Vue front end.
package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/hass"
	"github.com/playwjj/lanhound/internal/logx"
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

// HASS is the Home Assistant bridge as the web layer sees it.
type HASS interface {
	Config() hass.Config
	Status() hass.Status
	Put(hass.Config) (hass.Config, error)
	Test(hass.Config) error
}

// Server is the HTTP front of LanHound.
type Server struct {
	Registry *core.Registry
	Settings *core.Settings
	Hub      *core.Hub
	Scanner  Scanner
	Security Security
	Routers  *core.Routers // nil disables router sources
	HASS     HASS          // nil disables the Home Assistant bridge
	Services *core.ServiceScan
	Probes   *core.Probes
	Version  string
	Interval time.Duration
	// Password enables HTTP basic auth (any username) when non-empty.
	Password string

	started time.Time
	logins  *limiter
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
	Routers      []core.RouterStatus `json:"routers"`
	HASS         *hass.Status        `json:"hass,omitempty"`
	ServiceScan  bool                `json:"serviceScan"`
	Probes       []core.ProbeStatus  `json:"probes"`
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
	routers := []core.RouterStatus{}
	if s.Routers != nil {
		routers = s.Routers.Status()
	}
	var hs *hass.Status
	if s.HASS != nil {
		st := s.HASS.Status()
		hs = &st
	}
	ifaces := s.Scanner.Status()
	probes := []core.ProbeStatus{}
	if s.Probes != nil {
		ifaces = append(ifaces, s.Probes.Interfaces()...)
		probes = s.Probes.Status()
	}
	return Status{
		Probes:       probes,
		ServiceScan:  s.Services != nil && s.Services.Enabled(),
		HASS:         hs,
		Routers:      routers,
		Gateways:     gateways,
		Version:      s.Version,
		StartedAt:    s.started,
		Baseline:     s.Registry.Baseline(),
		ScanInterval: int(s.Interval / time.Second),
		Interfaces:   ifaces,
		Skipped:      skipped,
		Notify:       s.Settings.Get().Configured(),
		Alerts:       s.Registry.AlertStatus(),
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	s.started = time.Now()
	s.logins = newLimiter()
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
	mux.HandleFunc("GET /api/activity", s.activity)
	mux.HandleFunc("GET /api/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"version": s.Version, "startedAt": s.started, "logs": logx.Recent()})
	})
	mux.HandleFunc("GET /api/alerts", s.alerts)
	mux.HandleFunc("POST /api/alerts/{id}/trust", s.trustAlert)
	mux.HandleFunc("POST /api/ingest", s.ingest)
	mux.HandleFunc("GET /api/probes", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.probeList()) })
	mux.HandleFunc("POST /api/probes", s.addProbe)
	mux.HandleFunc("DELETE /api/probes/{id}", s.removeProbe)
	mux.HandleFunc("PUT /api/services", s.putServices)
	mux.HandleFunc("POST /api/devices/{id}/probe", s.probeDevice)
	mux.HandleFunc("GET /api/hass", s.getHASS)
	mux.HandleFunc("PUT /api/hass", s.putHASS)
	mux.HandleFunc("POST /api/hass/test", s.testHASS)
	mux.HandleFunc("GET /api/routers", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.routerStatus()) })
	mux.HandleFunc("PUT /api/routers", s.putRouters)
	mux.HandleFunc("POST /api/routers/test", s.testRouter)
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
		// Probes authenticate with their own token (checked in ingest).
		if s.Password != "" && r.URL.Path != "/api/ingest" {
			ip := clientIP(r)
			if left, locked := s.logins.locked(ip); locked {
				w.Header().Set("Retry-After", strconv.Itoa(int(left.Seconds())+1))
				http.Error(w, "too many wrong passwords, try again later", http.StatusTooManyRequests)
				return
			}
			_, pass, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(s.Password)) != 1 {
				if ok { // a wrong password, not the browser's first credential-less request
					s.logins.fail(ip)
				}
				w.Header().Set("WWW-Authenticate", `Basic realm="LanHound"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			s.logins.ok(ip)
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
	logx.L("web").Error("request failed", "err", err)
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
