// Package store persists devices, their MAC addresses, presence sessions
// and events in a single SQLite file — easy to back up, easy to move.
// It uses a pure-Go SQLite driver so the binary stays cgo-free.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/playwjj/lanhound/internal/services"
)

// Device is one physical device. It may own several MAC addresses once
// the user merges a phone's randomized MACs into it.
type Device struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Note           string   `json:"note"`
	Known          bool     `json:"known"`
	Hostname       string   `json:"hostname"`
	HostnameSource string   `json:"hostnameSource"`
	Model          string   `json:"model"`
	Vendor         string   `json:"vendor"`
	MAC            string   `json:"mac"` // most recently seen
	IP             string   `json:"ip"`
	IPv6           []string `json:"ipv6"` // most recent first
	DHCPFP         string   `json:"dhcpFingerprint"`
	Kind           string   `json:"kind"` // nas, camera, printer… from service probing

	Services   []services.Service `json:"services"`
	ServicesAt time.Time          `json:"servicesAt"` // zero: never probed

	// WiFi is a router's report that the device is associated to its
	// Wi-Fi (nil: no such report).
	WiFi      *WiFi     `json:"wifi,omitempty"`
	Iface     string    `json:"interface"`
	Online    bool      `json:"online"`
	Critical  bool      `json:"critical"` // alert when it goes offline
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// WiFi is a Wi-Fi association reported by a router.
type WiFi struct {
	Band   string    `json:"band,omitempty"`
	Signal int       `json:"signal,omitempty"`
	Radio  string    `json:"radio,omitempty"`
	Router string    `json:"router"` // the router source's label
	At     time.Time `json:"at"`
}

// Event kinds.
const (
	EventNew      = "new"
	EventOnline   = "online"
	EventOffline  = "offline"
	EventIP       = "ip"
	EventHostname = "hostname"
	EventMerged   = "merged"
)

// Event is one line of a device's history.
type Event struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

// Session is one continuous online period; End is zero while ongoing.
type Session struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// MAC is one hardware address owned by a device.
type MAC struct {
	MAC       string    `json:"mac"`
	DeviceID  int64     `json:"-"`
	FirstSeen time.Time `json:"firstSeen"`
}

// Store wraps the database.
//
// Writes go through one connection (SQLite has a single writer anyway).
// Reads — history, alerts, activity, settings — use a small separate
// pool: in WAL mode they then run alongside a write instead of queueing
// behind it.
type Store struct {
	db *sql.DB // the writer
	ro *sql.DB // readers (query_only)
}

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	id INTEGER PRIMARY KEY AUTOINCREMENT, -- never reuse IDs a browser may still hold
	name TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '',
	known INTEGER NOT NULL DEFAULT 0,
	hostname TEXT NOT NULL DEFAULT '',
	hostname_source TEXT NOT NULL DEFAULT '',
	model TEXT NOT NULL DEFAULT '',
	vendor TEXT NOT NULL DEFAULT '',
	mac TEXT NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	iface TEXT NOT NULL DEFAULT '',
	online INTEGER NOT NULL DEFAULT 0,
	first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS macs (
	mac TEXT PRIMARY KEY,
	device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	first_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS macs_device ON macs(device_id);
CREATE TABLE IF NOT EXISTS sessions (
	id INTEGER PRIMARY KEY,
	device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	start INTEGER NOT NULL,
	end INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id, start);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY,
	device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	at INTEGER NOT NULL,
	kind TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_device ON events(device_id, at);
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// Open opens (creating if needed) the database at path.
//
// The database holds secrets (bot tokens, router and MQTT passwords), so
// it and its WAL/SHM companions are kept readable by the owner only.
func Open(path string) (*Store, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create database: %w", err)
		}
		f.Close()
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite has a single writer anyway, and this keeps
	// the memory footprint small.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Tighten databases created by earlier versions (0644), and the WAL
	// and SHM files SQLite has created by now.
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(f, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, fmt.Errorf("protect %s: %w", f, err)
		}
	}
	ro, err := sql.Open("sqlite", dsn+"&_pragma=query_only(1)")
	if err != nil {
		db.Close()
		return nil, err
	}
	ro.SetMaxOpenConns(2) // each connection carries its own page cache
	return &Store{db: db, ro: ro}, nil
}

// migrations upgrade older databases; index i brings user_version i
// to i+1. Never edit a released entry, only append.
var migrations = []string{
	`ALTER TABLE devices ADD COLUMN critical INTEGER NOT NULL DEFAULT 0;
	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		at INTEGER NOT NULL,
		kind TEXT NOT NULL,
		device_id INTEGER,
		data TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS alerts_at ON alerts(at);`,
	`ALTER TABLE devices ADD COLUMN ipv6 TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE devices ADD COLUMN dhcp_fp TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE devices ADD COLUMN services TEXT NOT NULL DEFAULT '';
	ALTER TABLE devices ADD COLUMN kind TEXT NOT NULL DEFAULT '';
	ALTER TABLE devices ADD COLUMN services_at INTEGER NOT NULL DEFAULT 0;`,
	`ALTER TABLE devices ADD COLUMN wifi TEXT NOT NULL DEFAULT '';`,
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for ; v < len(migrations); v++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("to version %d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error {
	s.ro.Close()
	return s.db.Close()
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Devices loads every device and every MAC address.
func (s *Store) Devices() ([]*Device, []MAC, error) {
	rows, err := s.db.Query(`SELECT id, name, note, known, hostname, hostname_source, model, vendor, mac, ip, ipv6, dhcp_fp, kind, services, services_at, wifi, iface, online, critical, first_seen, last_seen FROM devices`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var devs []*Device
	for rows.Next() {
		d := &Device{}
		var known, online, critical int
		var ipv6, svcs, wifi string
		var svcAt int64
		var first, last int64
		if err := rows.Scan(&d.ID, &d.Name, &d.Note, &known, &d.Hostname, &d.HostnameSource, &d.Model, &d.Vendor, &d.MAC, &d.IP, &ipv6, &d.DHCPFP, &d.Kind, &svcs, &svcAt, &wifi, &d.Iface, &online, &critical, &first, &last); err != nil {
			return nil, nil, err
		}
		d.Known, d.Online, d.Critical = known != 0, online != 0, critical != 0
		d.IPv6 = splitList(ipv6)
		d.Services, d.ServicesAt = []services.Service{}, fromUnix(svcAt)
		if svcs != "" {
			_ = json.Unmarshal([]byte(svcs), &d.Services)
		}
		if wifi != "" {
			d.WiFi = &WiFi{}
			if json.Unmarshal([]byte(wifi), d.WiFi) != nil {
				d.WiFi = nil
			}
		}
		d.FirstSeen, d.LastSeen = fromUnix(first), fromUnix(last)
		devs = append(devs, d)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	mrows, err := s.db.Query(`SELECT mac, device_id, first_seen FROM macs`)
	if err != nil {
		return nil, nil, err
	}
	defer mrows.Close()
	var macs []MAC
	for mrows.Next() {
		var m MAC
		var first int64
		if err := mrows.Scan(&m.MAC, &m.DeviceID, &first); err != nil {
			return nil, nil, err
		}
		m.FirstSeen = fromUnix(first)
		macs = append(macs, m)
	}
	return devs, macs, mrows.Err()
}

// InsertDevice stores a new device together with its first MAC and sets d.ID.
func (s *Store) InsertDevice(d *Device) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO devices (name, note, known, hostname, hostname_source, model, vendor, mac, ip, ipv6, dhcp_fp, kind, services, services_at, wifi, iface, online, critical, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		d.Name, d.Note, b2i(d.Known), d.Hostname, d.HostnameSource, d.Model, d.Vendor, d.MAC, d.IP, strings.Join(d.IPv6, ","), d.DHCPFP, d.Kind, servicesJSON(d.Services), unix(d.ServicesAt), wifiJSON(d.WiFi), d.Iface, b2i(d.Online), b2i(d.Critical), unix(d.FirstSeen), unix(d.LastSeen))
	if err != nil {
		return err
	}
	if d.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO macs (mac, device_id, first_seen) VALUES (?,?,?)`, d.MAC, d.ID, unix(d.FirstSeen)); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateDevice writes every mutable field of d.
func (s *Store) UpdateDevice(d *Device) error {
	_, err := s.db.Exec(`UPDATE devices SET name=?, note=?, known=?, hostname=?, hostname_source=?, model=?, vendor=?, mac=?, ip=?, ipv6=?, dhcp_fp=?, kind=?, services=?, services_at=?, wifi=?, iface=?, online=?, critical=?, first_seen=?, last_seen=? WHERE id=?`,
		d.Name, d.Note, b2i(d.Known), d.Hostname, d.HostnameSource, d.Model, d.Vendor, d.MAC, d.IP, strings.Join(d.IPv6, ","), d.DHCPFP, d.Kind, servicesJSON(d.Services), unix(d.ServicesAt), wifiJSON(d.WiFi), d.Iface, b2i(d.Online), b2i(d.Critical), unix(d.FirstSeen), unix(d.LastSeen), d.ID)
	return err
}

// TouchDevices bulk-updates last-seen times.
func (s *Store) TouchDevices(lastSeen map[int64]time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`UPDATE devices SET last_seen=? WHERE id=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for id, t := range lastSeen {
		if _, err := stmt.Exec(unix(t), id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteDevice forgets a device, its MACs and its history.
func (s *Store) DeleteDevice(id int64) error {
	_, err := s.db.Exec(`DELETE FROM devices WHERE id=?`, id)
	return err
}

// Merge moves src's MACs, sessions and events to dst and deletes src.
// dst must already hold the merged field values (the caller decides
// which name/note/first-seen wins).
func (s *Store) Merge(src int64, dst *Device) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`UPDATE macs SET device_id=? WHERE device_id=?`,
		`UPDATE sessions SET device_id=? WHERE device_id=?`,
		`UPDATE events SET device_id=? WHERE device_id=?`,
		`UPDATE alerts SET device_id=? WHERE device_id=?`,
	} {
		if _, err := tx.Exec(q, dst.ID, src); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM devices WHERE id=?`, src); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE devices SET name=?, note=?, known=?, hostname=?, hostname_source=?, model=?, vendor=?, mac=?, ip=?, ipv6=?, dhcp_fp=?, kind=?, services=?, services_at=?, wifi=?, iface=?, online=?, critical=?, first_seen=?, last_seen=? WHERE id=?`,
		dst.Name, dst.Note, b2i(dst.Known), dst.Hostname, dst.HostnameSource, dst.Model, dst.Vendor, dst.MAC, dst.IP, strings.Join(dst.IPv6, ","), dst.DHCPFP, dst.Kind, servicesJSON(dst.Services), unix(dst.ServicesAt), wifiJSON(dst.WiFi), dst.Iface, b2i(dst.Online), b2i(dst.Critical), unix(dst.FirstSeen), unix(dst.LastSeen), dst.ID); err != nil {
		return err
	}
	// Two open sessions would overlap after a merge; close all but the latest.
	if _, err := tx.Exec(`UPDATE sessions SET end=? WHERE device_id=? AND end IS NULL AND id <> (SELECT MAX(id) FROM sessions WHERE device_id=? AND end IS NULL)`,
		unix(time.Now()), dst.ID, dst.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkAllKnown sets known=1 on every device.
func (s *Store) MarkAllKnown() error {
	_, err := s.db.Exec(`UPDATE devices SET known=1`)
	return err
}

// OpenSession starts an online period.
func (s *Store) OpenSession(deviceID int64, start time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions (device_id, start) VALUES (?,?)`, deviceID, unix(start))
	return err
}

// CloseSession ends the device's open online period, if any.
func (s *Store) CloseSession(deviceID int64, end time.Time) error {
	_, err := s.db.Exec(`UPDATE sessions SET end=? WHERE device_id=? AND end IS NULL`, unix(end), deviceID)
	return err
}

// AddEvent appends to a device's history.
func (s *Store) AddEvent(deviceID int64, at time.Time, kind, detail string) error {
	_, err := s.db.Exec(`INSERT INTO events (device_id, at, kind, detail) VALUES (?,?,?,?)`, deviceID, unix(at), kind, detail)
	return err
}

// Events returns a device's most recent events, newest first.
func (s *Store) Events(deviceID int64, limit int) ([]Event, error) {
	rows, err := s.ro.Query(`SELECT at, kind, detail FROM events WHERE device_id=? ORDER BY at DESC, id DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var at int64
		if err := rows.Scan(&at, &e.Kind, &e.Detail); err != nil {
			return nil, err
		}
		e.At = fromUnix(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Sessions returns a device's online periods overlapping [since, now],
// oldest first.
func (s *Store) Sessions(deviceID int64, since time.Time) ([]Session, error) {
	rows, err := s.ro.Query(`SELECT start, COALESCE(end, 0) FROM sessions WHERE device_id=? AND (end IS NULL OR end >= ?) ORDER BY start`, deviceID, unix(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var start, end int64
		if err := rows.Scan(&start, &end); err != nil {
			return nil, err
		}
		out = append(out, Session{Start: fromUnix(start), End: fromUnix(end)})
	}
	return out, rows.Err()
}

// Prune deletes history (events and closed sessions) older than before.
func (s *Store) Prune(before time.Time) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM events WHERE at < ?`,
		`DELETE FROM sessions WHERE end IS NOT NULL AND end < ?`,
		`DELETE FROM alerts WHERE at < ?`,
	} {
		res, err := s.db.Exec(q, unix(before))
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// Setting returns a stored setting, or "" when unset.
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.ro.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// Alert is one entry of the alert log. Data is the alert message as
// JSON (a notify.Message); the store does not interpret it.
type Alert struct {
	ID       int64           `json:"id"`
	At       time.Time       `json:"at"`
	Kind     string          `json:"kind"`
	DeviceID int64           `json:"deviceId,omitempty"`
	Data     json.RawMessage `json:"data"`
}

// AddAlert appends to the alert log and sets a.ID.
func (s *Store) AddAlert(a *Alert) error {
	var dev any
	if a.DeviceID != 0 {
		dev = a.DeviceID
	}
	res, err := s.db.Exec(`INSERT INTO alerts (at, kind, device_id, data) VALUES (?,?,?,?)`, unix(a.At), a.Kind, dev, string(a.Data))
	if err != nil {
		return err
	}
	a.ID, err = res.LastInsertId()
	return err
}

// Alerts returns the newest alerts, newest first.
func (s *Store) Alerts(limit int) ([]Alert, error) {
	rows, err := s.ro.Query(`SELECT id, at, kind, COALESCE(device_id, 0), data FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var at int64
		var data string
		if err := rows.Scan(&a.ID, &at, &a.Kind, &a.DeviceID, &data); err != nil {
			return nil, err
		}
		a.At, a.Data = fromUnix(at), json.RawMessage(data)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Alert returns one alert.
func (s *Store) Alert(id int64) (Alert, error) {
	var a Alert
	var at int64
	var data string
	err := s.ro.QueryRow(`SELECT id, at, kind, COALESCE(device_id, 0), data FROM alerts WHERE id=?`, id).Scan(&a.ID, &at, &a.Kind, &a.DeviceID, &data)
	a.At, a.Data = fromUnix(at), json.RawMessage(data)
	return a, err
}

// DeviceSession is a session with its device.
type DeviceSession struct {
	DeviceID int64
	Session
}

// AllSessions returns every device's online periods overlapping
// [since, now].
func (s *Store) AllSessions(since time.Time) ([]DeviceSession, error) {
	rows, err := s.ro.Query(`SELECT device_id, start, COALESCE(end, 0) FROM sessions WHERE end IS NULL OR end >= ?`, unix(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceSession
	for rows.Next() {
		var d DeviceSession
		var start, end int64
		if err := rows.Scan(&d.DeviceID, &start, &end); err != nil {
			return nil, err
		}
		d.Start, d.End = fromUnix(start), fromUnix(end)
		out = append(out, d)
	}
	return out, rows.Err()
}

func wifiJSON(w *WiFi) string {
	if w == nil {
		return ""
	}
	b, _ := json.Marshal(w)
	return string(b)
}

func servicesJSON(s []services.Service) string {
	if len(s) == 0 {
		return ""
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func splitList(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}
