package web

import (
	"net/http"
	"strconv"

	"github.com/playwjj/lanhound/internal/notify"
)

func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 31 {
		days = 7
	}
	a, err := s.Registry.Activity(days)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, a)
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
