// Package logx sets up LanHound's logging: leveled, structured logs on
// top of log/slog (text or JSON), a ring of recent warnings and errors
// for the web UI's diagnostics page, and a tracker that turns a failure
// retried every few seconds into one "broken" line and one "recovered"
// line instead of a log flood.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// L returns the logger for a component. It is looked up on every call so
// that package-level helpers pick up the configuration done in main.
func L(component string) *slog.Logger { return slog.Default().With("component", component) }

// Fatal logs at error level and exits — for startup failures.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// ParseLevel accepts debug, info, warn(ing) and error.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
}

// Setup installs the default logger: level and format ("text" or
// "json") from the environment, writing to w. Warnings and errors are
// also kept in the ring returned by Recent.
func Setup(level, format string, w io.Writer) error {
	lv, err := ParseLevel(level)
	if err != nil {
		return err
	}
	opts := &slog.HandlerOptions{Level: lv}
	var base slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		base = slog.NewTextHandler(w, opts)
	case "json":
		base = slog.NewJSONHandler(w, opts)
	default:
		return fmt.Errorf("unknown log format %q (want text or json)", format)
	}
	slog.SetDefault(slog.New(&ringHandler{next: base, ring: ring}))
	return nil
}

// Entry is one remembered warning or error.
type Entry struct {
	Time  time.Time         `json:"time"`
	Level string            `json:"level"`
	Msg   string            `json:"msg"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

const ringSize = 200

type entries struct {
	mu   sync.Mutex
	list []Entry // oldest first, at most ringSize
}

var ring = &entries{}

func (e *entries) add(en Entry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.list) == ringSize {
		copy(e.list, e.list[1:])
		e.list = e.list[:ringSize-1]
	}
	e.list = append(e.list, en)
}

// Recent returns the remembered warnings and errors, newest first.
func Recent() []Entry {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	out := make([]Entry, len(ring.list))
	for i, e := range ring.list {
		out[len(out)-1-i] = e
	}
	return out
}

// ringHandler passes records on and keeps warnings and errors.
type ringHandler struct {
	next  slog.Handler
	ring  *entries
	attrs []slog.Attr
}

func (h *ringHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelWarn || h.next.Enabled(ctx, l)
}

func (h *ringHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		en := Entry{Time: r.Time, Level: r.Level.String(), Msg: r.Message, Attrs: map[string]string{}}
		for _, a := range h.attrs {
			en.Attrs[a.Key] = a.Value.String()
		}
		r.Attrs(func(a slog.Attr) bool {
			en.Attrs[a.Key] = a.Value.String()
			return true
		})
		h.ring.add(en)
	}
	if !h.next.Enabled(ctx, r.Level) {
		return nil
	}
	return h.next.Handle(ctx, r)
}

func (h *ringHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &ringHandler{next: h.next.WithAttrs(as), ring: h.ring, attrs: append(append([]slog.Attr(nil), h.attrs...), as...)}
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	return &ringHandler{next: h.next.WithGroup(name), ring: h.ring, attrs: h.attrs}
}

// Failures tracks things that are retried (a router poll, an MQTT
// connection, a probe upload) so that an outage logs one warning when it
// starts, again only if the error changes, and one info line when it
// ends — not a line per retry.
type Failures struct {
	mu sync.Mutex
	m  map[string]*failure
}

type failure struct {
	since time.Time
	count int
	last  string
}

// Fail records a failure of key, logging when it is new or different.
func (f *Failures) Fail(l *slog.Logger, key, msg string, err error, args ...any) {
	f.mu.Lock()
	if f.m == nil {
		f.m = map[string]*failure{}
	}
	st := f.m[key]
	text := err.Error()
	first := st == nil
	if first {
		st = &failure{since: time.Now()}
		f.m[key] = st
	}
	st.count++
	changed := st.last != text
	st.last = text
	f.mu.Unlock()
	if first || changed {
		l.Warn(msg, append(args, "err", text)...)
	}
}

// OK records that key works; it logs recovery when key was failing.
func (f *Failures) OK(l *slog.Logger, key, msg string, args ...any) {
	f.mu.Lock()
	st := f.m[key]
	delete(f.m, key)
	f.mu.Unlock()
	if st != nil {
		l.Info(msg, append(args, "down_for", time.Since(st.since).Round(time.Second).String(), "failures", st.count)...)
	}
}
