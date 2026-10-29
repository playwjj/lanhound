// Package core is LanHound's brain: the device registry turns raw
// sightings into devices with an online/offline state machine and a
// history, decides when something deserves an alert, and fans changes
// out to live web clients.
package core

import (
	"encoding/json"
	"sync"
)

// Hub broadcasts JSON messages to live (SSE) subscribers.
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

// Message is the envelope sent to subscribers.
type Message struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// Subscribe returns a channel of encoded messages. The channel is closed
// when the subscriber falls too far behind or cancel is called; web
// clients reconnect and receive a fresh snapshot.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Publish sends a message to every subscriber without blocking.
func (h *Hub) Publish(typ string, data any) {
	b, err := json.Marshal(Message{Type: typ, Data: data})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default:
			delete(h.subs, ch)
			close(ch)
		}
	}
}
