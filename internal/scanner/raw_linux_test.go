//go:build linux && rawsock

// Real raw-socket test: builds a veth pair into a network namespace and
// runs the actual engine against it — AF_PACKET socket, BPF filter,
// ARP sweep, ICMPv6 all-nodes echo. Needs root, so CI runs it as
//
//	go test -c -tags rawsock -o scanner.test ./internal/scanner
//	sudo ./scanner.test -test.run TestRealLink -test.v
package scanner

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/lanhound/internal/netutil"
	"github.com/playwjj/lanhound/internal/passive"
)

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestRealLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a veth pair")
	}
	const ns, local, peer = "lhtest", "lhv0", "lhv1"
	_ = exec.Command("ip", "netns", "del", ns).Run()
	_ = exec.Command("ip", "link", "del", local).Run()
	sh(t, "ip", "netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", local).Run()
		_ = exec.Command("ip", "netns", "del", ns).Run()
	})
	sh(t, "ip", "link", "add", local, "type", "veth", "peer", "name", peer)
	sh(t, "ip", "link", "set", peer, "netns", ns)
	sh(t, "ip", "addr", "add", "10.99.0.1/24", "dev", local)
	sh(t, "ip", "link", "set", local, "up")
	sh(t, "ip", "netns", "exec", ns, "ip", "addr", "add", "10.99.0.2/24", "dev", peer)
	sh(t, "ip", "netns", "exec", ns, "ip", "link", "set", peer, "up")
	sh(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	peerMAC := sh(t, "ip", "netns", "exec", ns, "cat", "/sys/class/net/"+peer+"/address")

	// Wait for both link-local IPv6 addresses to finish duplicate address
	// detection, or echo replies come from nowhere.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		a := sh(t, "ip", "-6", "addr", "show", "dev", local, "scope", "link")
		b := sh(t, "ip", "netns", "exec", ns, "ip", "-6", "addr", "show", "dev", peer, "scope", "link")
		if strings.Contains(a, "fe80") && !strings.Contains(a, "tentative") && strings.Contains(b, "fe80") && !strings.Contains(b, "tentative") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	var mu sync.Mutex
	var ipv4, ipv6 bool
	targets, _ := netutil.Targets([]string{local})
	if len(targets) == 0 {
		t.Fatal("veth not detected as a scan target")
	}
	e := New(Config{
		Only: []string{local}, Interval: time.Hour, Window: 2 * time.Second, Rate: 1000, DHCPProbeEvery: -1,
		OnSighting: func(s passive.Sighting) {
			if s.MAC.String() != peerMAC {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if s.Source == passive.SrcARPReply && s.IP.Equal(net.ParseIP("10.99.0.2")) {
				ipv4 = true
			}
			if s.IP6 != nil && s.IP6.IsLinkLocalUnicast() {
				ipv6 = true
			}
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	select {
	case <-e.FirstRound():
	case <-time.After(30 * time.Second):
		t.Fatal("first sweep never finished")
	}
	mu.Lock()
	defer mu.Unlock()
	if !ipv4 {
		t.Error("ARP sweep did not find the peer")
	}
	if !ipv6 {
		t.Error("ff02::1 echo did not reveal the peer's link-local address")
	}
	st := e.Status()
	if len(st) != 1 || st[0].Error != "" || st[0].LastReplies != 1 {
		t.Errorf("status %+v", st)
	}
}

// TestRealMacvlan reproduces a Docker macvlan container on the scanning
// host: frames the host sends on the parent never reach the container,
// so it must be heard passively (its frames show up as outgoing on the
// parent) or asked through a macvlan shim, which netutil folds into the
// parent's target.
func TestRealMacvlan(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create macvlan interfaces")
	}
	const ns, parent, ctr, shim = "lhmv", "lhd0", "lhc0", "lhs0"
	cleanup := func() {
		_ = exec.Command("ip", "link", "del", parent).Run()
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
	cleanup()
	t.Cleanup(cleanup)
	sh(t, "ip", "netns", "add", ns)
	sh(t, "ip", "link", "add", parent, "type", "dummy")
	sh(t, "ip", "addr", "add", "10.98.0.1/24", "dev", parent)
	sh(t, "ip", "link", "set", parent, "up")
	sh(t, "ip", "link", "add", ctr, "link", parent, "type", "macvlan", "mode", "bridge")
	sh(t, "ip", "link", "set", ctr, "netns", ns)
	sh(t, "ip", "netns", "exec", ns, "ip", "addr", "add", "10.98.0.2/24", "dev", ctr)
	sh(t, "ip", "netns", "exec", ns, "ip", "link", "set", ctr, "up")
	ctrMAC := sh(t, "ip", "netns", "exec", ns, "cat", "/sys/class/net/"+ctr+"/address")

	run := func(t *testing.T, chatter bool) (found map[string]bool, st []Status) {
		t.Helper()
		var mu sync.Mutex
		found = map[string]bool{}
		e := New(Config{
			Only: []string{parent}, Interval: time.Hour, Window: 2 * time.Second, Rate: 1000, DHCPProbeEvery: -1,
			OnSighting: func(s passive.Sighting) {
				if s.MAC.String() == ctrMAC && s.IP != nil && s.IP.Equal(net.ParseIP("10.98.0.2")) {
					mu.Lock()
					found[s.Source+" "+s.Iface] = true
					mu.Unlock()
				}
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go e.Run(ctx)
		if chatter {
			// The container ARPs for its gateway; nobody answers.
			go func() {
				time.Sleep(500 * time.Millisecond)
				_ = exec.Command("ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", "10.98.0.254").Run()
			}()
		}
		select {
		case <-e.FirstRound():
		case <-time.After(30 * time.Second):
			t.Fatal("first sweep never finished")
		}
		mu.Lock()
		defer mu.Unlock()
		return found, e.Status()
	}

	t.Run("passive", func(t *testing.T) {
		found, st := run(t, true)
		if found["arp-reply "+parent] {
			t.Error("the parent's own sweep reached its macvlan child; the premise of the shim is wrong")
		}
		if !found["arp "+parent] {
			t.Errorf("container's ARP request was not heard on the parent: %v", found)
		}
		if len(st) != 1 || st[0].Shim != "" {
			t.Errorf("status %+v", st)
		}
	})

	t.Run("shim", func(t *testing.T) {
		sh(t, "ip", "link", "add", shim, "link", parent, "type", "macvlan", "mode", "bridge")
		sh(t, "ip", "addr", "add", "10.98.0.3/24", "dev", shim)
		sh(t, "ip", "link", "set", shim, "up")
		found, st := run(t, false)
		if !found["arp-reply "+parent] {
			t.Errorf("sweep through the shim did not find the container: %v", found)
		}
		if len(st) != 1 || st[0].Interface != parent || st[0].Shim != shim || st[0].Error != "" {
			t.Errorf("status %+v", st)
		}
	})
}
