package netutil

import (
	"net"
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
