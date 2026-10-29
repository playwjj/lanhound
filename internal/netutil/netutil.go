// Package netutil finds the interfaces and subnets LanHound should scan.
// Zero configuration: every up, non-loopback interface with a private
// IPv4 address becomes a scan target, one per broadcast domain.
package netutil

import (
	"encoding/binary"
	"net"
)

// MaxHosts caps the scan size per interface. Larger networks are skipped
// (with the reason reported) instead of flooding a big subnet with ARP.
const MaxHosts = 65534

// Target is one interface + subnet to scan.
type Target struct {
	Iface   net.Interface
	IP      net.IP     // our IPv4 address on this interface
	Network *net.IPNet // the subnet
	Hosts   []net.IP   // every usable host address except our own
}

// Targets enumerates scannable interfaces. skipped collects human-readable
// reasons for interfaces that were considered but rejected.
func Targets() (targets []Target, skipped []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, []string{err.Error()}
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || !ip4.IsPrivate() {
				continue
			}
			hosts, ok := hostList(ipnet, ip4)
			if !ok {
				skipped = append(skipped, iface.Name+": network larger than /16, skipped")
				continue
			}
			targets = append(targets, Target{Iface: iface, IP: ip4, Network: ipnet, Hosts: hosts})
		}
	}
	return targets, skipped
}

// hostList returns the usable host addresses of ipnet except self.
// ok=false when the network has more than MaxHosts addresses.
func hostList(ipnet *net.IPNet, self net.IP) (hosts []net.IP, ok bool) {
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, false
	}
	hostBits := bits - ones
	if hostBits > 16 {
		return nil, false
	}
	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	total := uint32(1) << hostBits
	for i := uint32(0); i < total; i++ {
		if hostBits >= 2 && (i == 0 || i == total-1) {
			continue // network and broadcast addresses
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, base+i)
		ip := net.IP(b)
		if ip.Equal(self) {
			continue
		}
		hosts = append(hosts, ip)
	}
	return hosts, true
}
