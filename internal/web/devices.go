package web

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/core"
)

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
	_ = cw.Write([]string{"name", "hostname", "ip", "ipv6", "mac", "all_macs", "randomized", "link", "link_certain", "vendor", "model", "interface", "known", "online", "first_seen", "last_seen", "note"})
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339)
	}
	for _, d := range s.Registry.Devices() {
		_ = cw.Write([]string{
			csvSafe(d.Name), csvSafe(d.Hostname), d.IP, strings.Join(d.IPv6, " "), d.MAC, strings.Join(d.MACs, " "), strconv.FormatBool(d.Randomized), linkType(d.Link), strconv.FormatBool(d.Link != nil && d.Link.Certain),
			csvSafe(d.Vendor), csvSafe(d.Model), d.Iface, strconv.FormatBool(d.Known), strconv.FormatBool(d.Online),
			ts(d.FirstSeen), ts(d.LastSeen), csvSafe(d.Note),
		})
	}
	cw.Flush()
}

func linkType(l *core.Link) string {
	if l == nil {
		return ""
	}
	return l.Type
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

// probeDevice probes one device now — an explicit user request, so it
// runs even when background scanning is off.
func (s *Server) probeDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.Registry.Device(id); err != nil {
		fail(w, err)
		return
	}
	if s.Services != nil {
		s.Services.ProbeNow(id)
	}
	writeJSON(w, map[string]bool{"ok": true})
}
