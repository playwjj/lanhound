// Package agent is `lanhound agent`: a probe that scans the segment it
// sits on and uploads what it sees to a central LanHound. Put one on each
// VLAN or guest network the central instance cannot reach with ARP.
//
// The agent keeps no database and serves no UI. If the central instance
// is unreachable it buffers sightings (bounded) and catches up later.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/netutil"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/scanner"
)

const (
	uploadEvery = 2 * time.Second
	maxBuffered = 5000
)

// Agent buffers sightings and uploads them.
type Agent struct {
	Server  string // central LanHound, e.g. http://192.168.2.22:8686
	Token   string
	Version string
	Status  func() []scanner.Status // the local engine's interfaces

	client *http.Client

	mu      sync.Mutex
	pending []core.WireSighting
	dropped int
}

// Collect is the engine's OnSighting callback.
func (a *Agent) Collect(s passive.Sighting) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pending) >= maxBuffered {
		a.pending = a.pending[1:] // keep the newest
		a.dropped++
	}
	a.pending = append(a.pending, core.ToWire(s))
}

// ErrUnauthorized means the central instance rejected the token.
var ErrUnauthorized = errors.New("central LanHound rejected the probe token (removed, or mistyped?)")

// Run uploads until ctx is done. It returns ErrUnauthorized when the
// token is refused, since retrying cannot help.
func (a *Agent) Run(ctx context.Context) error {
	if a.client == nil {
		a.client = &http.Client{Timeout: 15 * time.Second}
	}
	t := time.NewTicker(uploadEvery)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		err := a.flush(ctx)
		switch {
		case errors.Is(err, ErrUnauthorized):
			return err
		case err != nil && !failing:
			log.Printf("agent: upload failed, buffering: %v", err)
			failing = true
		case err == nil && failing:
			log.Printf("agent: connected to %s again", a.Server)
			failing = false
		}
	}
}

// flush sends everything pending plus the interface status.
func (a *Agent) flush(ctx context.Context) error {
	a.mu.Lock()
	batch := a.pending
	a.pending = nil
	dropped := a.dropped
	a.dropped = 0
	a.mu.Unlock()
	if dropped > 0 {
		log.Printf("agent: buffer full, dropped %d old sightings", dropped)
	}

	up := core.Upload{Version: a.Version, Sightings: batch, Gateways: map[string][]string{}}
	if up.Sightings == nil {
		up.Sightings = []core.WireSighting{}
	}
	if a.Status != nil {
		up.Interfaces = a.Status()
	}
	for iface, ips := range netutil.Gateways() {
		for _, ip := range ips {
			up.Gateways[iface] = append(up.Gateways[iface], ip.String())
		}
	}
	err := a.post(ctx, up)
	if err != nil {
		a.mu.Lock()
		a.pending = append(batch, a.pending...) // retry later, oldest first
		if over := len(a.pending) - maxBuffered; over > 0 {
			a.pending = a.pending[over:]
		}
		a.mu.Unlock()
	}
	return err
}

func (a *Agent) post(ctx context.Context, up core.Upload) error {
	body, _ := json.Marshal(up)
	url := strings.TrimRight(a.Server, "/") + "/api/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("X-LanHound", "agent")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("%s: HTTP %d %s", url, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
