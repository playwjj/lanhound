package passive

import (
	"encoding/binary"
	"net"
)

// ICMPv6 types LanHound reads.
const (
	icmp6EchoRequest = 128
	icmp6EchoReply   = 129
	icmp6RouterAdv   = 134
	icmp6NeighSol    = 135
	icmp6NeighAdv    = 136

	protoICMPv6 = 58
)

// AllNodes is ff02::1; every IPv6 host answers an echo sent there.
var AllNodes = net.ParseIP("ff02::1")

// decodeIPv6 reads neighbour discovery and echo replies. The Ethernet
// source is the device; the IPv6 source (or, for a duplicate-address
// probe from ::, the address being claimed) is one of its addresses.
func decodeIPv6(frame []byte) []Sighting {
	ip := frame[14:]
	if len(ip) < 40+8 || ip[0]>>4 != 6 || ip[6] != protoICMPv6 {
		return nil // extension headers before ICMPv6 are not followed
	}
	src := net.IP(append([]byte(nil), ip[8:24]...))
	icmp := ip[40:]
	if l := int(binary.BigEndian.Uint16(ip[4:6])); l >= 8 && l < len(icmp) {
		icmp = icmp[:l]
	}
	s := Sighting{MAC: net.HardwareAddr(append([]byte(nil), frame[6:12]...)), Source: SrcNDP}
	switch icmp[0] {
	case icmp6EchoReply, icmp6RouterAdv, icmp6NeighAdv:
		s.IP6 = src
	case icmp6NeighSol:
		if src.IsUnspecified() && len(icmp) >= 24 { // duplicate address detection
			s.IP6 = net.IP(append([]byte(nil), icmp[8:24]...))
		} else {
			s.IP6 = src
		}
	default:
		return nil
	}
	if s.IP6.IsUnspecified() || s.IP6.IsMulticast() {
		s.IP6 = nil
	}
	return []Sighting{s}
}

// BuildEchoAllNodes returns an ICMPv6 echo request from mac/src to
// ff02::1 — the IPv6 counterpart of an ARP sweep in a single packet.
func BuildEchoAllNodes(mac net.HardwareAddr, src net.IP, id, seq uint16) []byte {
	src = src.To16()
	payload := []byte("lanhound")
	icmp := make([]byte, 8+len(payload))
	icmp[0] = icmp6EchoRequest
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], icmp6Checksum(src, AllNodes, icmp))

	frame := make([]byte, 14+40+len(icmp))
	copy(frame[0:6], []byte{0x33, 0x33, 0, 0, 0, 1}) // multicast MAC of ff02::1
	copy(frame[6:12], mac)
	frame[12], frame[13] = 0x86, 0xdd
	ip := frame[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmp)))
	ip[6], ip[7] = protoICMPv6, 1 // hop limit 1: link-local only
	copy(ip[8:24], src)
	copy(ip[24:40], AllNodes)
	copy(frame[54:], icmp)
	return frame
}

func icmp6Checksum(src, dst net.IP, msg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src.To16())
	add(dst.To16())
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[0:4], uint32(len(msg)))
	pseudo[7] = protoICMPv6
	add(pseudo[:])
	add(msg)
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
