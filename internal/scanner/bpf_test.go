package scanner

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/playwjj/lanhound/internal/arp"
)

func udp(sport, dport uint16, frag uint16) []byte {
	f := make([]byte, 14+20+8+4)
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[20:22], frag)
	f[23] = 17
	binary.BigEndian.PutUint16(f[34:36], sport)
	binary.BigEndian.PutUint16(f[36:38], dport)
	return f
}

func TestFilter(t *testing.T) {
	vm, err := bpf.NewVM(filter())
	if err != nil {
		t.Fatal(err)
	}
	arpFrame, _ := arp.BuildRequest(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1))
	tcp := udp(443, 50000, 0)
	tcp[23] = 6
	ipv6 := make([]byte, 70)
	ipv6[12], ipv6[13] = 0x86, 0xdd
	ipv6[20] = 17 // UDP
	icmp6 := make([]byte, 70)
	icmp6[12], icmp6[13] = 0x86, 0xdd
	icmp6[20] = 58

	cases := []struct {
		name  string
		frame []byte
		keep  bool
	}{
		{"arp", arpFrame, true},
		{"dhcp request", udp(68, 67, 0), true},
		{"dhcp reply", udp(67, 68, 0), true},
		{"mdns", udp(5353, 5353, 0), true},
		{"ssdp m-search", udp(51000, 1900, 0), true},
		{"ssdp reply", udp(1900, 51000, 0), true},
		{"nbns", udp(137, 137, 0), true},
		{"dns", udp(53, 51000, 0), false},
		{"tcp", tcp, false},
		{"fragment", udp(5353, 5353, 0x0010), false},
		{"ipv6 udp", ipv6, false},
		{"icmpv6", icmp6, true},
	}
	for _, c := range cases {
		n, err := vm.Run(c.frame)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (n > 0) != c.keep {
			t.Errorf("%s: keep=%v, want %v", c.name, n > 0, c.keep)
		}
	}
}
