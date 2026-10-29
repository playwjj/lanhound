package web

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Login throttling: after maxFailures wrong passwords from one address
// within failureWindow, that address is locked out for lockout. It only
// slows guessing; the UI password is a LAN convenience, not a vault.
const (
	maxFailures   = 5
	failureWindow = 10 * time.Minute
	lockout       = 15 * time.Minute
)

type attempt struct {
	failures int
	first    time.Time
	locked   time.Time // zero unless locked out
}

type limiter struct {
	mu  sync.Mutex
	ip  map[string]*attempt
	now func() time.Time
}

func newLimiter() *limiter { return &limiter{ip: map[string]*attempt{}, now: time.Now} }

// clientIP is the TCP peer. X-Forwarded-For is deliberately ignored: a
// client could set it to anything and dodge the lockout.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// locked reports whether ip is locked out and for how long.
func (l *limiter) locked(ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.ip[ip]
	if a == nil || a.locked.IsZero() {
		return 0, false
	}
	if left := a.locked.Add(lockout).Sub(l.now()); left > 0 {
		return left, true
	}
	delete(l.ip, ip)
	return 0, false
}

// fail records a wrong password.
func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	a := l.ip[ip]
	if a == nil || now.Sub(a.first) > failureWindow {
		a = &attempt{first: now}
		l.ip[ip] = a
	}
	a.failures++
	if a.failures >= maxFailures {
		a.locked = now
	}
	if len(l.ip) > 10000 { // bound memory against address spraying
		for k, v := range l.ip {
			if v.locked.IsZero() && now.Sub(v.first) > failureWindow {
				delete(l.ip, k)
			}
		}
	}
}

// ok clears an address after a correct password.
func (l *limiter) ok(ip string) {
	l.mu.Lock()
	delete(l.ip, ip)
	l.mu.Unlock()
}
