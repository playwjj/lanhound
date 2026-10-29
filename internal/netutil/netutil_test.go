package netutil

import (
	"net"
	"strings"
	"testing"
)

func TestHostListStartsAtNetworkAddress(t *testing.T) {
	// As returned by Interface.Addrs: the host's own address plus mask.
	self := net.IPv4(10, 77, 0, 5).To4()
	ipnet := &net.IPNet{IP: self, Mask: net.CIDRMask(24, 32)}
	hosts, ok := hostList(ipnet, self)
	if !ok {
		t.Fatal("a /24 must be scannable")
	}
	if len(hosts) != 253 {
		t.Fatalf("want 253 hosts (254 usable minus self), got %d", len(hosts))
	}
	if !hosts[0].Equal(net.IPv4(10, 77, 0, 1)) || !hosts[len(hosts)-1].Equal(net.IPv4(10, 77, 0, 254)) {
		t.Fatalf("range %s … %s", hosts[0], hosts[len(hosts)-1])
	}
	for _, h := range hosts {
		if h.Equal(self) {
			t.Fatal("own address must be excluded")
		}
	}
}

func TestHostListTooLarge(t *testing.T) {
	if _, ok := hostList(&net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(15, 32)}, net.IPv4(10, 0, 0, 1)); ok {
		t.Fatal("a /15 must be refused")
	}
}

func TestIsVirtual(t *testing.T) {
	for name, want := range map[string]bool{
		"docker0": true, "br-f6ed7b574ccd": true, "veth3a1b2c": true, "virbr0": true, "lxdbr0": true, "cni0": true,
		"eth0": false, "enxa0cec8d68b90": false, "wlan0": false, "br0": false, "br-lan": false, "enp3s0": false,
	} {
		if got := IsVirtual(name); got != want {
			t.Errorf("IsVirtual(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseRoutes(t *testing.T) {
	table := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
enxa0cec8d68b90	00000000	0102A8C0	0003	0	0	100	00000000	0	0	0
enxa0cec8d68b90	0002A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
wlan0	00000000	FE02A8C0	0003	0	0	600	00000000	0	0	0
`
	got := parseRoutes(strings.NewReader(table))
	if len(got) != 2 || !got["enxa0cec8d68b90"][0].Equal(net.IPv4(192, 168, 2, 1)) || !got["wlan0"][0].Equal(net.IPv4(192, 168, 2, 254)) {
		t.Fatalf("got %v", got)
	}
}
