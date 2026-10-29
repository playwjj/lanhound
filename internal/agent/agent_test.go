package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/scanner"
)

func sighting(last byte) passive.Sighting {
	return passive.Sighting{Iface: "eth0", MAC: net.HardwareAddr{0x24, 0x0a, 0xc4, 0, 0, last}, IP: net.IPv4(192, 168, 50, last).To4(), Source: passive.SrcARPReply, At: time.Now()}
}

func TestFlushBuffersWhileServerIsDown(t *testing.T) {
	var mu sync.Mutex
	var got []core.Upload
	up := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer lhp_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !up {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		var u core.Upload
		_ = json.NewDecoder(r.Body).Decode(&u)
		got = append(got, u)
	}))
	defer srv.Close()

	a := &Agent{Server: srv.URL, Token: "lhp_test", Version: "v9", client: srv.Client(),
		Status: func() []scanner.Status { return []scanner.Status{{Interface: "eth0", Network: "192.168.50.0/24"}} }}
	a.Collect(sighting(1))
	a.Collect(sighting(2))
	if err := a.flush(context.Background()); err == nil {
		t.Fatal("server down: flush must fail")
	}
	a.Collect(sighting(3))
	mu.Lock()
	up = true
	mu.Unlock()
	if err := a.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Sightings) != 3 || got[0].Sightings[0].MAC != "24:0a:c4:00:00:01" || got[0].Interfaces[0].Network != "192.168.50.0/24" {
		t.Fatalf("uploads %+v", got)
	}
	// Nothing pending: the next flush is a heartbeat with no sightings.
	_ = a.flush(context.Background())
	if len(got) != 2 || len(got[1].Sightings) != 0 {
		t.Fatalf("heartbeat %+v", got[1])
	}

	bad := &Agent{Server: srv.URL, Token: "lhp_wrong", client: srv.Client()}
	if err := bad.Run(context.Background()); err != ErrUnauthorized {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestBufferIsBounded(t *testing.T) {
	a := &Agent{}
	for i := 0; i < maxBuffered+10; i++ {
		a.Collect(sighting(byte(i)))
	}
	if len(a.pending) != maxBuffered || a.dropped != 10 {
		t.Fatalf("pending %d dropped %d", len(a.pending), a.dropped)
	}
}
