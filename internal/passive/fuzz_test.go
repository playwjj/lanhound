package passive

import (
	"net"
	"testing"

	"github.com/playwjj/lanhound/internal/arp"
)

// Frames come straight off the wire: any device on the LAN can send
// LanHound arbitrary bytes. Decoding must never panic.
func FuzzDecode(f *testing.F) {
	frame, _ := arp.BuildRequest(devMAC, devIP, net.IPv4(192, 168, 2, 1))
	f.Add(frame)
	f.Add(BuildDHCPDiscover(devMAC, 1))
	f.Add(BuildEchoAllNodes(devMAC, net.ParseIP("fe80::1"), 1, 1))
	f.Add(udpFrame(devMAC, devIP, 5353, 5353, []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c}))
	f.Add(udpFrame(devMAC, devIP, 137, 137, make([]byte, 60)))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = Decode(b)
	})
}

func FuzzReadName(f *testing.F) {
	f.Add([]byte{3, 'f', 'o', 'o', 0}, 0)
	f.Add([]byte{0xc0, 0x00}, 0)
	f.Fuzz(func(t *testing.T, b []byte, off int) {
		if off < 0 {
			off = -off
		}
		_, _, _ = readName(b, off)
	})
}
