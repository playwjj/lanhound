package passive

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
)

const (
	dnsTypeA   = 1
	dnsTypeTXT = 16
)

// decodeMDNS reads an mDNS response for the sender's own hostname (an A
// record pointing at the sender's IP) and a product hint from TXT
// records. Records about other hosts are ignored: Bonjour sleep proxies
// answer on behalf of sleeping devices and would misattribute names.
func decodeMDNS(msg []byte, s *Sighting) {
	if len(msg) < 12 || msg[2]&0x80 == 0 { // queries carry nothing but presence
		return
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	rr := int(binary.BigEndian.Uint16(msg[6:8])) + int(binary.BigEndian.Uint16(msg[8:10])) + int(binary.BigEndian.Uint16(msg[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		_, n, ok := readName(msg, off)
		if !ok || n+4 > len(msg) {
			return
		}
		off = n + 4
	}
	for i := 0; i < rr && i < 64; i++ {
		name, n, ok := readName(msg, off)
		if !ok || n+10 > len(msg) {
			return
		}
		typ := binary.BigEndian.Uint16(msg[n : n+2])
		rdlen := int(binary.BigEndian.Uint16(msg[n+8 : n+10]))
		rdata := n + 10
		if rdata+rdlen > len(msg) {
			return
		}
		data := msg[rdata : rdata+rdlen]
		switch typ {
		case dnsTypeA:
			if rdlen == 4 && s.IP != nil && net.IP(data).Equal(s.IP) && s.Hostname == "" {
				if h := cleanName(strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local")); h != "" {
					s.Hostname, s.HostnameSource = h, SrcMDNS
				}
			}
		case dnsTypeTXT:
			if s.Model == "" {
				s.Model = txtModel(data)
			}
		}
		off = rdata + rdlen
	}
}

// txtModel pulls a human-readable product name out of a DNS-SD TXT
// record: md= (Google Cast), model= (_device-info), am= (AirPlay),
// ty= (printers).
func txtModel(data []byte) string {
	found := map[string]string{}
	for i := 0; i < len(data); {
		l := int(data[i])
		if i+1+l > len(data) {
			break
		}
		kv := data[i+1 : i+1+l]
		if k, v, ok := bytes.Cut(kv, []byte("=")); ok {
			found[strings.ToLower(string(k))] = string(v)
		}
		i += 1 + l
	}
	for _, k := range []string{"md", "model", "am", "ty", "usb_mdl"} {
		if v := cleanName(found[k]); v != "" {
			return v
		}
	}
	return ""
}

// readName decodes a possibly-compressed DNS name starting at off. It
// returns the dotted name and the offset just past the name in the
// original (uncompressed) position.
func readName(msg []byte, off int) (name string, next int, ok bool) {
	var sb strings.Builder
	jumped := false
	for hops := 0; hops < 32; hops++ {
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if !jumped {
				next = off + 1
			}
			return sb.String(), next, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, false
			}
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
		case l&0xc0 != 0:
			return "", 0, false
		default:
			if off+1+l > len(msg) {
				return "", 0, false
			}
			sb.Write(msg[off+1 : off+1+l])
			sb.WriteByte('.')
			off += 1 + l
		}
	}
	return "", 0, false
}
