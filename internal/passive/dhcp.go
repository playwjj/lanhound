package passive

import (
	"net"
)

const (
	bootpFixedLen = 236
	dhcpMagic     = 0x63825363

	optHostname    = 12
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
	return []Sighting{s}
}

// decodeDHCPReply handles server → client messages. The server is a
// device too; an ACK also tells us which address the client now holds.
func decodeDHCPReply(payload []byte, base Sighting) []Sighting {
	m, ok := parseBOOTP(payload)
	if !ok || m.op != 2 {
		return nil
	}
	base.Source = SrcDHCP
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
