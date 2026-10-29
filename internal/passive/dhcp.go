package passive

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

const (
	bootpFixedLen = 236
	dhcpMagic     = 0x63825363

	optHostname    = 12
	optParamList   = 55
	optVendorClass = 60
	optRequestedIP = 50
	optMsgType     = 53
	optServerID    = 54
	optEnd         = 255
	optPad         = 0

	dhcpAck = 5
)

type bootp struct {
	op      byte
	ciaddr  net.IP
	yiaddr  net.IP
	chaddr  net.HardwareAddr
	options map[byte][]byte
}

func parseBOOTP(b []byte) (m bootp, ok bool) {
	if len(b) < bootpFixedLen+4 || b[1] != 1 || b[2] != 6 { // htype Ethernet, hlen 6
		return m, false
	}
	if uint32(b[236])<<24|uint32(b[237])<<16|uint32(b[238])<<8|uint32(b[239]) != dhcpMagic {
		return m, false
	}
	m.op = b[0]
	m.ciaddr = net.IP(append([]byte(nil), b[12:16]...))
	m.yiaddr = net.IP(append([]byte(nil), b[16:20]...))
	m.chaddr = net.HardwareAddr(append([]byte(nil), b[28:34]...))
	m.options = make(map[byte][]byte)
	opts := b[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == optEnd {
			break
		}
		if code == optPad {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		m.options[code] = opts[i+2 : i+2+l]
		i += 2 + l
	}
	return m, true
}

// decodeDHCPRequest handles client → server messages (DISCOVER, REQUEST,
// INFORM). The client hardware address is taken from chaddr, and the
// hostname from option 12 — the single best naming source on a home LAN.
func decodeDHCPRequest(payload []byte, base Sighting) []Sighting {
	m, ok := parseBOOTP(payload)
	if !ok || m.op != 1 {
		return nil
	}
	s := Sighting{MAC: m.chaddr, Source: SrcDHCP}
	switch {
	case base.IP != nil:
		s.IP = base.IP
	case !m.ciaddr.IsUnspecified():
		s.IP = m.ciaddr
	}
	if name := cleanName(string(m.options[optHostname])); name != "" {
		s.Hostname, s.HostnameSource = name, SrcDHCP
	}
	s.DHCPFingerprint = dhcpFingerprint(m)
	return []Sighting{s}
}

func dhcpFingerprint(m bootp) string {
	prl := m.options[optParamList]
	if len(prl) == 0 {
		return ""
	}
	parts := make([]string, len(prl))
	for i, o := range prl {
		parts[i] = strconv.Itoa(int(o))
	}
	return strings.Join(parts, ",") + "|" + cleanName(string(m.options[optVendorClass]))
}

// decodeDHCPReply handles server → client messages. The server is a
// device too; an ACK also tells us which address the client now holds.
func decodeDHCPReply(payload []byte, base Sighting) []Sighting {
	m, ok := parseBOOTP(payload)
	if !ok || m.op != 2 {
		return nil
	}
	base.Source = SrcDHCP
	base.DHCPServer = true
	if id := m.options[optServerID]; len(id) == 4 {
		base.DHCPServerID = net.IP(append([]byte(nil), id...))
	}
	out := []Sighting{base}
	if t := m.options[optMsgType]; len(t) == 1 && t[0] == dhcpAck && !m.yiaddr.IsUnspecified() {
		out = append(out, Sighting{MAC: m.chaddr, IP: m.yiaddr, Source: SrcDHCP})
	}
	return out
}

// cleanName trims a device-supplied name to something safe to display.
func cleanName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == 0 {
			break
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
		if len(out) >= 63 {
			break
		}
	}
	for len(out) > 0 && (out[len(out)-1] == ' ' || out[len(out)-1] == '.') {
		out = out[:len(out)-1]
	}
	return string(out)
}

// BuildDHCPDiscover returns a broadcast DHCPDISCOVER Ethernet frame
// from mac. LanHound sends one now and then to learn which DHCP servers
// answer on the segment; it never follows up with a REQUEST, so no
// lease is taken. The broadcast flag makes servers broadcast their
// OFFER, which the passive listener then sees.
func BuildDHCPDiscover(mac net.HardwareAddr, xid uint32) []byte {
	bootp := make([]byte, 300) // BOOTP minimum size
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
	binary.BigEndian.PutUint32(bootp[4:8], xid)
	bootp[10] = 0x80 // broadcast flag
	copy(bootp[28:34], mac)
	binary.BigEndian.PutUint32(bootp[236:240], dhcpMagic)
	opts := []byte{
		optMsgType, 1, 1, // DHCPDISCOVER
		55, 4, 1, 3, 6, 54, // parameter request list: mask, router, DNS, server ID
		optEnd,
	}
	copy(bootp[240:], opts)

	frame := make([]byte, 14+20+8+len(bootp))
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], mac)
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(bootp)))
	copy(ip[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], PortDHCPClient)
	binary.BigEndian.PutUint16(udp[2:4], PortDHCPServer)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(bootp))) // checksum 0: optional for IPv4
	copy(frame[42:], bootp)
	return frame
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
