package store

import (
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDeviceLifecycle(t *testing.T) {
	s := open(t)
	now := time.Unix(1_800_000_000, 0)
	d := &Device{MAC: "aa:bb:cc:00:00:01", IP: "192.168.1.5", Iface: "eth0", Online: true, FirstSeen: now, LastSeen: now}
	if err := s.InsertDevice(d); err != nil {
		t.Fatal(err)
	}
	if d.ID == 0 {
		t.Fatal("ID not set")
	}
	d.Name, d.Known = "NAS", true
	if err := s.UpdateDevice(d); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchDevices(map[int64]time.Time{d.ID: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	devs, macs, err := s.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].Name != "NAS" || !devs[0].Known || !devs[0].LastSeen.Equal(now.Add(time.Minute)) {
		t.Fatalf("devices %+v", devs[0])
	}
	if len(macs) != 1 || macs[0].DeviceID != d.ID {
		t.Fatalf("macs %+v", macs)
	}
}

func TestSessionsEventsAndPrune(t *testing.T) {
	s := open(t)
	t0 := time.Unix(1_800_000_000, 0)
	d := &Device{MAC: "aa:bb:cc:00:00:02", FirstSeen: t0, LastSeen: t0}
	if err := s.InsertDevice(d); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.OpenSession(d.ID, t0))
	must(s.CloseSession(d.ID, t0.Add(time.Hour)))
	must(s.OpenSession(d.ID, t0.Add(2*time.Hour)))
	must(s.AddEvent(d.ID, t0, EventNew, "192.168.1.9"))
	must(s.AddEvent(d.ID, t0.Add(time.Hour), EventOffline, ""))

	sess, err := s.Sessions(d.ID, t0.Add(-time.Hour))
	must(err)
	if len(sess) != 2 || !sess[1].End.IsZero() {
		t.Fatalf("sessions %+v", sess)
	}
	ev, err := s.Events(d.ID, 10)
	must(err)
	if len(ev) != 2 || ev[0].Kind != EventOffline {
		t.Fatalf("events %+v", ev)
	}

	n, err := s.Prune(t0.Add(90 * time.Minute))
	must(err)
	if n != 3 { // 2 events + 1 closed session; the open session stays
		t.Fatalf("pruned %d", n)
	}
}

func TestMerge(t *testing.T) {
	s := open(t)
	t0 := time.Unix(1_800_000_000, 0)
	old := &Device{MAC: "aa:00:00:00:00:01", Name: "Mom's phone", FirstSeen: t0, LastSeen: t0}
	nu := &Device{MAC: "da:00:00:00:00:02", FirstSeen: t0.Add(time.Hour), LastSeen: t0.Add(time.Hour), Online: true}
	for _, d := range []*Device{old, nu} {
		if err := s.InsertDevice(d); err != nil {
			t.Fatal(err)
		}
		if err := s.OpenSession(d.ID, d.FirstSeen); err != nil {
			t.Fatal(err)
		}
	}
	old.MAC, old.Online, old.LastSeen = nu.MAC, true, nu.LastSeen
	if err := s.Merge(nu.ID, old); err != nil {
		t.Fatal(err)
	}
	devs, macs, _ := s.Devices()
	if len(devs) != 1 || devs[0].ID != old.ID || devs[0].MAC != nu.MAC {
		t.Fatalf("devices %+v", devs)
	}
	if len(macs) != 2 || macs[0].DeviceID != old.ID || macs[1].DeviceID != old.ID {
		t.Fatalf("macs %+v", macs)
	}
	sess, _ := s.Sessions(old.ID, time.Time{})
	open := 0
	for _, x := range sess {
		if x.End.IsZero() {
			open++
		}
	}
	if len(sess) != 2 || open != 1 {
		t.Fatalf("sessions %+v", sess)
	}
}

func TestSettings(t *testing.T) {
	s := open(t)
	if v, err := s.Setting("x"); err != nil || v != "" {
		t.Fatal(v, err)
	}
	_ = s.SetSetting("x", "1")
	_ = s.SetSetting("x", "2")
	if v, _ := s.Setting("x"); v != "2" {
		t.Fatal(v)
	}
}

func TestAlertsAndCritical(t *testing.T) {
	s := open(t)
	t0 := time.Unix(1_800_000_000, 0)
	d := &Device{MAC: "aa:bb:cc:00:00:09", Critical: true, FirstSeen: t0, LastSeen: t0}
	if err := s.InsertDevice(d); err != nil {
		t.Fatal(err)
	}
	devs, _, _ := s.Devices()
	if !devs[0].Critical {
		t.Fatal("critical flag not stored")
	}
	a := &Alert{At: t0, Kind: "device_offline", DeviceID: d.ID, Data: []byte(`{"event":"device_offline"}`)}
	if err := s.AddAlert(a); err != nil || a.ID == 0 {
		t.Fatal(err)
	}
	_ = s.AddAlert(&Alert{At: t0.Add(2 * time.Second), Kind: "rogue_dhcp", Data: []byte(`{}`)})
	list, err := s.Alerts(10)
	if err != nil || len(list) != 2 || list[0].Kind != "rogue_dhcp" || list[1].DeviceID != d.ID {
		t.Fatalf("alerts %+v %v", list, err)
	}
	if n, _ := s.Prune(t0.Add(time.Second)); n != 1 {
		t.Fatalf("pruned %d", n)
	}
}

func TestMigrateLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate a v0.1.0 database: no critical column, no alerts table.
	for _, q := range []string{`DROP TABLE alerts`, `ALTER TABLE devices DROP COLUMN critical`, `PRAGMA user_version = 0`} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Alerts(1); err != nil {
		t.Fatal("alerts table missing after migration:", err)
	}
	var v int
	_ = s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != len(migrations) {
		t.Fatalf("user_version %d", v)
	}
}
