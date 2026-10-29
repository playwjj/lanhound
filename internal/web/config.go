package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/hass"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/router"
)

// ingest receives a remote probe's upload. It authenticates with the
// probe's bearer token, not the UI password.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if s.Probes == nil {
		http.Error(w, "probes disabled", http.StatusNotFound)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "missing probe token", http.StatusUnauthorized)
		return
	}
	var u core.Upload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&u); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Probes.Ingest(token, u); err != nil {
		if errors.Is(err, core.ErrBadToken) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) probeList() []core.ProbeStatus {
	if s.Probes == nil {
		return []core.ProbeStatus{}
	}
	return s.Probes.Status()
}

func (s *Server) addProbe(w http.ResponseWriter, r *http.Request) {
	if s.Probes == nil {
		http.Error(w, "probes disabled", http.StatusNotFound)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	p, token, err := s.Probes.Add(body.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Hub.Publish("status", s.Status())
	writeJSON(w, map[string]any{"probe": p, "token": token})
}

func (s *Server) removeProbe(w http.ResponseWriter, r *http.Request) {
	if s.Probes == nil {
		http.Error(w, "probes disabled", http.StatusNotFound)
		return
	}
	if err := s.Probes.Remove(r.PathValue("id")); err != nil {
		fail(w, err)
		return
	}
	s.Hub.Publish("status", s.Status())
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) putServices(w http.ResponseWriter, r *http.Request) {
	if s.Services == nil {
		http.Error(w, "service scanning unavailable", http.StatusNotFound)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.Services.SetEnabled(body.Enabled); err != nil {
		fail(w, err)
		return
	}
	s.Hub.Publish("status", s.Status())
	writeJSON(w, map[string]bool{"enabled": body.Enabled})
}

func (s *Server) getHASS(w http.ResponseWriter, r *http.Request) {
	if s.HASS == nil {
		http.Error(w, "Home Assistant bridge disabled", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"config": s.HASS.Config(), "status": s.HASS.Status()})
}

func (s *Server) putHASS(w http.ResponseWriter, r *http.Request) {
	if s.HASS == nil {
		http.Error(w, "Home Assistant bridge disabled", http.StatusNotFound)
		return
	}
	var c hass.Config
	if !readJSON(w, r, &c) {
		return
	}
	cfg, err := s.HASS.Put(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"config": cfg, "status": s.HASS.Status()})
}

func (s *Server) testHASS(w http.ResponseWriter, r *http.Request) {
	if s.HASS == nil {
		http.Error(w, "Home Assistant bridge disabled", http.StatusNotFound)
		return
	}
	var c hass.Config
	if !readJSON(w, r, &c) {
		return
	}
	if err := s.HASS.Test(c); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) routerStatus() []core.RouterStatus {
	if s.Routers == nil {
		return []core.RouterStatus{}
	}
	return s.Routers.Status()
}

func (s *Server) putRouters(w http.ResponseWriter, r *http.Request) {
	if s.Routers == nil {
		http.Error(w, "router sources are disabled", http.StatusNotFound)
		return
	}
	var list []router.Config
	if !readJSON(w, r, &list) {
		return
	}
	st, err := s.Routers.Put(list)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Hub.Publish("status", s.Status())
	writeJSON(w, st)
}

func (s *Server) testRouter(w http.ResponseWriter, r *http.Request) {
	if s.Routers == nil {
		http.Error(w, "router sources are disabled", http.StatusNotFound)
		return
	}
	var c router.Config
	if !readJSON(w, r, &c) {
		return
	}
	writeJSON(w, s.Routers.Test(r.Context(), c))
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
