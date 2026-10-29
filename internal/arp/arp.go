// Package arp builds and parses Ethernet ARP frames.
// It is pure byte work (no syscalls) so it can be unit tested anywhere.
package arp

import (
	"errors"
	"net"
)

const (
	EtherTypeARP = 0x0806
	OpRequest    = 1
	OpReply      = 2
	frameLen     = 42 // 14-byte Ethernet header + 28-byte ARP payload
)

// BuildRequest returns a full Ethernet+ARP request frame asking
// "who has targetIP" from srcMAC/srcIP, broadcast to ff:ff:ff:ff:ff:ff.
func BuildRequest(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) ([]byte, error) {
	src4, tgt4 := srcIP.To4(), targetIP.To4()
	if src4 == nil || tgt4 == nil {
		return nil, errors.New("arp: IPv4 addresses required")
	}
	if len(srcMAC) != 6 {
		return nil, errors.New("arp: source MAC must be 6 bytes")
	}
	frame := make([]byte, frameLen)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff // broadcast destination
	}
	copy(frame[6:12], srcMAC)
	frame[12], frame[13] = 0x08, 0x06 // EtherType ARP

	p := frame[14:]
	p[0], p[1] = 0, 1       // hardware type: Ethernet
	p[2], p[3] = 0x08, 0x00 // protocol type: IPv4
	p[4], p[5] = 6, 4       // hardware/protocol address lengths
	p[6], p[7] = 0, OpRequest
	copy(p[8:14], srcMAC)
	copy(p[14:18], src4)
	// p[18:24] target MAC stays zeroed (that is the question being asked)
	copy(p[24:28], tgt4)
	return frame, nil
}

// Packet holds the fields of a parsed ARP payload that LanHound cares about.
type Packet struct {
	Op        uint16
	SenderMAC net.HardwareAddr
	SenderIP  net.IP
	TargetMAC net.HardwareAddr
	TargetIP  net.IP
}

// Parse extracts ARP information from a raw Ethernet frame.
// ok is false when the frame is not an Ethernet/IPv4 ARP packet.
// VLAN-tagged frames are not handled yet and report ok=false.
func Parse(frame []byte) (pkt Packet, ok bool) {
	if len(frame) < frameLen {
		return pkt, false
	}
	if frame[12] != 0x08 || frame[13] != 0x06 {
		return pkt, false
	}
	p := frame[14:]
	if p[0] != 0 || p[1] != 1 || p[2] != 0x08 || p[3] != 0x00 || p[4] != 6 || p[5] != 4 {
		return pkt, false
	}
	pkt.Op = uint16(p[6])<<8 | uint16(p[7])
	pkt.SenderMAC = net.HardwareAddr(append([]byte(nil), p[8:14]...))
	pkt.SenderIP = net.IP(append([]byte(nil), p[14:18]...))
	pkt.TargetMAC = net.HardwareAddr(append([]byte(nil), p[18:24]...))
	pkt.TargetIP = net.IP(append([]byte(nil), p[24:28]...))
	return pkt, true
}
