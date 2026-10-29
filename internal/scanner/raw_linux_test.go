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
