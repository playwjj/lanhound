package router

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// openWrt reads an OpenWrt router through the same ubus JSON-RPC
// endpoint LuCI uses (/ubus, uhttpd-mod-ubus). It logs in with the
// router's own account and calls two read-only methods from
// rpcd-mod-luci, both part of every LuCI install:
//
//	luci-rpc getDHCPLeases  current DHCP leases with hostnames
//	luci-rpc getHostHints   every host the router knows (neighbour
//	                        table, leases, /etc/ethers) on all its LANs
type openWrt struct {
	cfg    Config
	client *http.Client

	mu  sync.Mutex
	sid string // ubus session, reused until it expires
}

const nullSession = "00000000000000000000000000000000"

// ubus status codes (libubox/ubus.h) worth naming in errors.
var ubusStatus = map[int]string{
	3: "method not found (is LuCI / rpcd-mod-luci installed?)",
	4: "not found",
	6: "permission denied",
	7: "timeout",
}

func newOpenWrt(cfg Config) *openWrt {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user opted in for a self-signed router cert
	}
	return &openWrt{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second, Transport: tr}}
}

func (o *openWrt) endpoint() string {
	u := strings.TrimRight(o.cfg.URL, "/")
	if !strings.HasSuffix(u, "/ubus") {
		u += "/ubus"
	}
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	return u
}

var errSession = errors.New("ubus session expired")

// call performs one ubus call and returns the result payload.
func (o *openWrt) call(ctx context.Context, sid, object, method string, args any) (json.RawMessage, error) {
	if args == nil {
		args = map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "call",
		"params": []any{sid, object, method, args},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d (is this an OpenWrt LuCI address?)", o.endpoint(), resp.StatusCode)
	}
	var r struct {
		Result []json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: not a ubus JSON-RPC answer", o.endpoint())
	}
	if r.Error != nil {
		if r.Error.Code == -32002 { // "Access denied": session unknown or expired
			return nil, errSession
		}
		return nil, fmt.Errorf("ubus %s.%s: %s", object, method, r.Error.Message)
	}
	if len(r.Result) == 0 {
		return nil, fmt.Errorf("ubus %s.%s: empty result", object, method)
	}
	var status int
	if err := json.Unmarshal(r.Result[0], &status); err != nil {
		return nil, fmt.Errorf("ubus %s.%s: bad status", object, method)
	}
	if status != 0 {
		if status == 6 && sid != nullSession {
			return nil, errSession
		}
		msg := ubusStatus[status]
		if msg == "" {
			msg = fmt.Sprintf("status %d", status)
		}
		return nil, fmt.Errorf("ubus %s.%s: %s", object, method, msg)
	}
	if len(r.Result) < 2 {
		return json.RawMessage("{}"), nil
	}
	return r.Result[1], nil
}

func (o *openWrt) login(ctx context.Context) (string, error) {
	user := o.cfg.Username
	if user == "" {
		user = "root"
	}
	res, err := o.call(ctx, nullSession, "session", "login", map[string]string{"username": user, "password": o.cfg.Password})
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return "", errors.New("login failed: wrong username or password")
		}
		return "", err
	}
	var s struct {
		Session string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(res, &s); err != nil || s.Session == "" {
		return "", errors.New("login failed: no session returned")
	}
	return s.Session, nil
}

// session returns a valid session id, logging in when needed.
func (o *openWrt) session(ctx context.Context, renew bool) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sid != "" && !renew {
		return o.sid, nil
	}
	sid, err := o.login(ctx)
	if err != nil {
		return "", err
	}
	o.sid = sid
	return sid, nil
}

// authed calls a method, logging in again once if the session expired.
func (o *openWrt) authed(ctx context.Context, object, method string) (json.RawMessage, error) {
	sid, err := o.session(ctx, false)
	if err != nil {
		return nil, err
	}
	res, err := o.call(ctx, sid, object, method, nil)
	if errors.Is(err, errSession) {
		if sid, err = o.session(ctx, true); err != nil {
			return nil, err
		}
		res, err = o.call(ctx, sid, object, method, nil)
	}
	if errors.Is(err, errSession) {
		return nil, fmt.Errorf("ubus %s.%s: permission denied for this account", object, method)
	}
	return res, err
}

func (o *openWrt) Fetch(ctx context.Context) ([]Entry, error) {
	var entries []Entry

	res, err := o.authed(ctx, "luci-rpc", "getDHCPLeases")
	if err != nil {
		return nil, err
	}
	var leases struct {
		DHCP []struct {
			Hostname string `json:"hostname"`
			IP       string `json:"ipaddr"`
			MAC      string `json:"macaddr"`
		} `json:"dhcp_leases"`
	}
	if err := json.Unmarshal(res, &leases); err != nil {
		return nil, fmt.Errorf("getDHCPLeases: %w", err)
	}
	for _, l := range leases.DHCP {
		if mac, err := net.ParseMAC(l.MAC); err == nil {
			entries = append(entries, Entry{MAC: mac, IP: net.ParseIP(l.IP), Hostname: l.Hostname})
		}
	}

	// Host hints add devices with static addresses and the router's
	// neighbours on every LAN. Older LuCI lacks the method; leases alone
	// are still useful then.
	res, err = o.authed(ctx, "luci-rpc", "getHostHints")
	if err == nil {
		var hints map[string]struct {
			Name    string   `json:"name"`
			IPAddrs []string `json:"ipaddrs"`
		}
		if json.Unmarshal(res, &hints) == nil {
			for macStr, h := range hints {
				mac, err := net.ParseMAC(macStr)
				if err != nil {
					continue
				}
				e := Entry{MAC: mac, Hostname: h.Name}
				for _, a := range h.IPAddrs {
					if ip := net.ParseIP(a).To4(); ip != nil {
						e.IP = ip
						break
					}
				}
				entries = append(entries, e)
			}
		}
	}
	return merge(entries), nil
}
