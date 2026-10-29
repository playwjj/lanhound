package passive

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/playwjj/lanhound/internal/arp"
)

var (
	devMAC = net.HardwareAddr{0x24, 0x0a, 0xc4, 0x01, 0x02, 0x03}
	devIP  = net.IPv4(192, 168, 2, 87).To4()
)

// udpFrame wraps payload in Ethernet/IPv4/UDP headers (checksums unset —
// the decoder does not verify them).
func udpFrame(srcMAC net.HardwareAddr, srcIP net.IP, sport, dport uint16, payload []byte) []byte {
	f := make([]byte, 14+20+8+len(payload))
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], srcMAC)
	f[12], f[13] = 0x08, 0x00
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], []byte{255, 255, 255, 255})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	return f
}

func bootpMsg(op byte, chaddr net.HardwareAddr, yiaddr net.IP, opts ...[]byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = op, 1, 6
	if yiaddr != nil {
		copy(b[16:20], yiaddr.To4())
	}
	copy(b[28:34], chaddr)
	binary.BigEndian.PutUint32(b[236:240], dhcpMagic)
	for _, o := range opts {
		b = append(b, o...)
	}
	return append(b, optEnd)
}

func opt(code byte, data ...byte) []byte { return append([]byte{code, byte(len(data))}, data...) }

func TestDecodeARP(t *testing.T) {
	frame, _ := arp.BuildRequest(devMAC, devIP, net.IPv4(192, 168, 2, 1))
	got := Decode(frame)
	if len(got) != 1 || got[0].Source != SrcARP || !got[0].IP.Equal(devIP) || got[0].MAC.String() != devMAC.String() {
		t.Fatalf("got %+v", got)
	}
	if got[0].Gratuitous {
		t.Fatal("ordinary request flagged gratuitous")
	}
	garp, _ := arp.BuildRequest(devMAC, devIP, devIP)
	if got := Decode(garp); !got[0].Gratuitous {
		t.Fatal("gratuitous ARP not flagged")
	}
	probe, _ := arp.BuildRequest(devMAC, net.IPv4zero, net.IPv4(192, 168, 2, 9))
	if got := Decode(probe); len(got) != 1 || got[0].IP != nil {
		t.Fatalf("ARP probe should yield a MAC-only sighting, got %+v", got)
	}
}

func TestDecodeDHCPRequestHostname(t *testing.T) {
	msg := bootpMsg(1, devMAC, nil, opt(optMsgType, 3), opt(optHostname, []byte("Pixel-8\x00")...))
	got := Decode(udpFrame(devMAC, net.IPv4zero, 68, 67, msg))
	if len(got) != 1 {
		t.Fatalf("want 1 sighting, got %d", len(got))
	}
	s := got[0]
	if s.Hostname != "Pixel-8" || s.HostnameSource != SrcDHCP || s.IP != nil || s.MAC.String() != devMAC.String() {
		t.Fatalf("got %+v", s)
	}
}

func TestDecodeDHCPAck(t *testing.T) {
	server := net.HardwareAddr{0x8c, 0x3b, 0xad, 0, 0, 1}
	msg := bootpMsg(2, devMAC, devIP, opt(optMsgType, dhcpAck), opt(optServerID, 192, 168, 2, 1))
	got := Decode(udpFrame(server, net.IPv4(192, 168, 2, 1), 67, 68, msg))
	if len(got) != 2 {
		t.Fatalf("want server + client sightings, got %+v", got)
	}
	if !got[0].DHCPServer || !got[0].DHCPServerID.Equal(net.IPv4(192, 168, 2, 1)) || got[1].DHCPServer {
		t.Fatalf("server sighting not flagged: %+v", got[0])
	}
	if !got[1].IP.Equal(devIP) || got[1].MAC.String() != devMAC.String() {
		t.Fatalf("client sighting wrong: %+v", got[1])
	}
}

func dnsName(s string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func rr(name []byte, typ uint16, data []byte) []byte {
	b := append([]byte(nil), name...)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, 0x8001)
	b = binary.BigEndian.AppendUint32(b, 120)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func TestDecodeMDNSResponse(t *testing.T) {
	msg := []byte{0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0}
	// A record for another host (sleep proxy) must not name the sender.
	msg = append(msg, rr(dnsName("other.local"), dnsTypeA, []byte{192, 168, 2, 50})...)
	hostOff := len(msg)
	msg = append(msg, rr(dnsName("Living-Room-TV.local"), dnsTypeA, devIP)...)
	txt := []byte{}
	for _, kv := range []string{"id=abc", "md=Chromecast Ultra"} {
		txt = append(txt, byte(len(kv)))
		txt = append(txt, kv...)
	}
	// TXT record whose owner name is a compression pointer.
	msg = append(msg, rr([]byte{0xc0, byte(hostOff)}, dnsTypeTXT, txt)...)

	got := Decode(udpFrame(devMAC, devIP, 5353, 5353, msg))
	if len(got) != 1 {
		t.Fatalf("got %d sightings", len(got))
	}
	if got[0].Hostname != "Living-Room-TV" || got[0].Model != "Chromecast Ultra" {
		t.Fatalf("got %+v", got[0])
	}
}

func TestReadNameLoop(t *testing.T) {
	msg := []byte{0xc0, 0x00} // pointer to itself
	if _, _, ok := readName(msg, 0); ok {
		t.Fatal("pointer loop must fail")
	}
}

func TestDecodeSSDP(t *testing.T) {
	p := []byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nServer: Linux/4.9 UPnP/1.0 Roku/11.5\r\n\r\n")
	got := Decode(udpFrame(devMAC, devIP, 50000, 1900, p))
	if len(got) != 1 || got[0].Model != "Linux/4.9 UPnP/1.0 Roku/11.5" {
		t.Fatalf("got %+v", got)
	}
}

func encodeNetBIOS(name string, suffix byte) []byte {
	raw := []byte(name + strings.Repeat(" ", 15-len(name)))
	raw = append(raw, suffix)
	b := []byte{0x20}
	for _, c := range raw {
		b = append(b, 'A'+c>>4, 'A'+c&0x0f)
	}
	return append(b, 0)
}

func TestDecodeNBNSRegistration(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1} // opcode 5, 1 question
	msg = append(msg, encodeNetBIOS("DESKTOP-7Q2", 0x00)...)
	msg = append(msg, 0, 0x20, 0, 1)
	got := Decode(udpFrame(devMAC, devIP, 137, 137, msg))
	if len(got) != 1 || got[0].Hostname != "DESKTOP-7Q2" || got[0].HostnameSource != SrcNBNS {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeIgnoresOtherTraffic(t *testing.T) {
	if got := Decode(udpFrame(devMAC, devIP, 443, 50000, []byte("x"))); got != nil {
		t.Fatalf("unrelated UDP should be ignored, got %+v", got)
	}
	if got := Decode([]byte{1, 2, 3}); got != nil {
		t.Fatal("short frame should be ignored")
	}
}

func TestCleanName(t *testing.T) {
	if got := cleanName("ab\x01c. \x00junk"); got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildDHCPDiscover(t *testing.T) {
	frame := BuildDHCPDiscover(devMAC, 0xdeadbeef)
	if ipChecksum(frame[14:34]) != 0 {
		t.Fatal("bad IPv4 header checksum")
	}
	got := Decode(frame)
	if len(got) != 1 || got[0].Source != SrcDHCP || got[0].MAC.String() != devMAC.String() || got[0].IP != nil {
		t.Fatalf("our own discover should decode as a DHCP client sighting: %+v", got)
	}
	m, ok := parseBOOTP(frame[42:])
	if !ok || m.options[optMsgType][0] != 1 || frame[42+10] != 0x80 {
		t.Fatal("not a broadcast DHCPDISCOVER")
	}
}
