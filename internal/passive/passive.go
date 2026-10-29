// Package passive decodes the broadcast/multicast chatter devices emit on
// their own — ARP, DHCP, mDNS, SSDP and NetBIOS name registrations — into
// sightings. It is pure byte work (no syscalls) so it is unit tested
// anywhere; the scanner feeds it frames captured from a raw socket.
//
// Passive listening is what keeps the new-device alert latency low: a
// phone joining the network broadcasts a DHCP request (usually carrying
// its hostname) seconds before the next ARP sweep would find it.
package passive

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/playwjj/lanhound/internal/arp"
)

// Sources of a sighting.
const (
	SrcARPReply = "arp-reply" // answered one of our ARP requests
	SrcARP      = "arp"       // overheard ARP traffic
	SrcDHCP     = "dhcp"
	SrcMDNS     = "mdns"
	SrcSSDP     = "ssdp"
	SrcNBNS     = "nbns"
	SrcRDNS     = "rdns" // reverse DNS answer from the LAN's resolver (set by the probe package)
)

// UDP ports the passive listener cares about.
const (
	PortDHCPServer = 67
	PortDHCPClient = 68
	PortNBNS       = 137
	PortSSDP       = 1900
	PortMDNS       = 5353
)

// Sighting is evidence that a device is present, plus whatever it told
// us about itself along the way.
type Sighting struct {
	Iface          string
	MAC            net.HardwareAddr
	IP             net.IP // nil when the frame carried no usable address (e.g. DHCPDISCOVER)
	Source         string
	Hostname       string
	HostnameSource string // which protocol named it; see HostnamePriority
	Model          string // product hint: mDNS TXT md=/model=, SSDP SERVER header
	At             time.Time

	// Gratuitous marks an unsolicited ARP announcement (sender IP equals
	// target IP) — normal after a reboot, suspicious in a flood.
	Gratuitous bool
	// DHCPServer marks a DHCP server answering (OFFER/ACK/NAK); MAC/IP
	// are the server's and DHCPServerID is its option-54 identifier.
	DHCPServer   bool
	DHCPServerID net.IP
}

// HostnamePriority ranks hostname sources: a name the device chose for
// itself in DHCP beats an mDNS announcement, which beats NetBIOS and
// whatever the router's DNS made up.
func HostnamePriority(src string) int {
	switch src {
	case SrcDHCP:
		return 4
	case SrcMDNS:
		return 3
	case SrcNBNS:
		return 2
	case SrcRDNS:
		return 1
	}
	return 0
}

// Decode turns one raw Ethernet frame into zero or more sightings.
// A DHCP ACK, for example, names both the server that sent it and the
// client it addresses. Iface and At are left for the caller to fill.
func Decode(frame []byte) []Sighting {
	if len(frame) < 14 {
		return nil
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case arp.EtherTypeARP:
		pkt, ok := arp.Parse(frame)
		if !ok {
			return nil
		}
		s := Sighting{MAC: pkt.SenderMAC, Source: SrcARP, Gratuitous: pkt.SenderIP.Equal(pkt.TargetIP)}
		if pkt.Op == arp.OpReply {
			s.Source = SrcARPReply
		}
		if !pkt.SenderIP.IsUnspecified() { // RFC 5227 probes come from 0.0.0.0
			s.IP = pkt.SenderIP
		}
		return []Sighting{s}
	case 0x0800:
		return decodeIPv4(frame)
	}
	return nil
}

func decodeIPv4(frame []byte) []Sighting {
	ip := frame[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return nil
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 || ip[9] != 17 {
		return nil
	}
	if binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 {
		return nil // non-first fragment
	}
	srcMAC := net.HardwareAddr(append([]byte(nil), frame[6:12]...))
	srcIP := net.IP(append([]byte(nil), ip[12:16]...))
	udp := ip[ihl:]
	sport := binary.BigEndian.Uint16(udp[0:2])
	dport := binary.BigEndian.Uint16(udp[2:4])
	payload := udp[8:]
	if l := int(binary.BigEndian.Uint16(udp[4:6])); l >= 8 && l-8 < len(payload) {
		payload = payload[:l-8] // drop Ethernet padding
	}

	base := Sighting{MAC: srcMAC, IP: srcIP}
	if srcIP.IsUnspecified() {
		base.IP = nil
	}
	switch {
	case dport == PortDHCPServer && sport == PortDHCPClient:
		return decodeDHCPRequest(payload, base)
	case sport == PortDHCPServer && dport == PortDHCPClient:
		return decodeDHCPReply(payload, base)
	case sport == PortMDNS:
		base.Source = SrcMDNS
		decodeMDNS(payload, &base)
		return []Sighting{base}
	case sport == PortSSDP || dport == PortSSDP:
		base.Source = SrcSSDP
		base.Model = ssdpServer(payload)
		return []Sighting{base}
	case sport == PortNBNS && dport == PortNBNS:
		base.Source = SrcNBNS
		if name := nbnsRegistration(payload); name != "" {
			base.Hostname, base.HostnameSource = name, SrcNBNS
		}
		return []Sighting{base}
	}
	return nil
}
