// Package netutil finds the interfaces and subnets LanHound should scan.
// Zero configuration: every up, non-loopback interface with a private
// IPv4 address becomes a scan target, one per broadcast domain.
package netutil

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

	// Shim is a macvlan interface the host has on Iface in the same
	// subnet, or nil. The kernel never delivers frames the host sends
	// on Iface to Iface's own macvlan children (Docker macvlan
	// containers), but a sibling macvlan in bridge mode reaches them:
	// sweeping from the shim is the only way to ask them directly.
	Shim *Shim
}

// Shim is the macvlan interface a Target sweeps from.
type Shim struct {
	Iface net.Interface
	IP    net.IP
}

// virtualIface matches bridges and links that container and VM runtimes
// create on the host (docker0, Docker's br-<12 hex>, veth pairs,
// libvirt, LXD, Kubernetes CNIs). They are private subnets too, but not
// the home LAN: sweeping them finds containers and wastes a /16 of ARP.
// User bridges such as br0 or OpenWrt's br-lan do not match.
var virtualIface = regexp.MustCompile(`^(docker\d+|br-[0-9a-f]{12}|veth.*|virbr\d+|lxdbr\d+|lxcbr\d+|cni\d+|flannel\..*|cali.*|vxlan\..*|kube-.*|podman\d+)$`)

// IsVirtual reports whether name looks like a container/VM interface.
func IsVirtual(name string) bool { return virtualIface.MatchString(name) }

// Targets enumerates scannable interfaces. Container/VM interfaces are
// skipped unless named in include. skipped collects human-readable
// reasons for interfaces that were considered but rejected.
func Targets(include []string) (targets []Target, skipped []string) {
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
		if IsVirtual(iface.Name) && !contains(include, iface.Name) {
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
			// Addrs reports the interface's own address with the mask;
			// the network itself starts at the masked address.
			network := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}
			hosts, ok := hostList(network, ip4)
			if !ok {
				skipped = append(skipped, iface.Name+": network larger than /16, skipped")
				continue
			}
			targets = append(targets, Target{Iface: iface, IP: ip4, Network: network, Hosts: hosts})
		}
	}
	return foldShims(targets), skipped
}

// macvlanParentFunc is swapped out in tests.
var macvlanParentFunc = macvlanParent

// macvlanParent returns the interface a macvlan interface sits on, or ""
// when name is not one (or this is not Linux). Older kernels put no
// DEVTYPE in sysfs, so a macvlan is recognised by its shape: stacked on
// exactly one lower device, not a bridge or bond, and with a MAC of its
// own — which also rules out VLANs and ipvlans, whose frames carry the
// parent's MAC and so could never be told apart from the host's own.
func macvlanParent(name string) string {
	dir := filepath.Join("/sys/class/net", name)
	for _, sub := range []string{"bridge", "bonding"} {
		if _, err := os.Stat(filepath.Join(dir, sub)); err == nil {
			return ""
		}
	}
	lower, _ := filepath.Glob(filepath.Join(dir, "lower_*"))
	if len(lower) != 1 {
		return ""
	}
	mac, err1 := os.ReadFile(filepath.Join(dir, "address"))
	parentMAC, err2 := os.ReadFile(filepath.Join(lower[0], "address"))
	if err1 != nil || err2 != nil || string(mac) == string(parentMAC) {
		return ""
	}
	return strings.TrimPrefix(filepath.Base(lower[0]), "lower_")
}

// foldShims turns a macvlan target with an address in its parent's
// subnet (whatever its own mask, often /32) into that parent's Shim, so the segment is still watched once and under
// the parent's name.
func foldShims(targets []Target) []Target {
	folded := map[int]bool{}
	for i, t := range targets {
		parent := macvlanParentFunc(t.Iface.Name)
		if parent == "" {
			continue
		}
		for j := range targets {
			p := &targets[j]
			if j != i && !folded[j] && p.Shim == nil && p.Iface.Name == parent && p.Network.Contains(t.IP) {
				p.Shim = &Shim{Iface: t.Iface, IP: t.IP}
				folded[i] = true
				break
			}
		}
	}
	var out []Target
	for i, t := range targets {
		if !folded[i] {
			out = append(out, t)
		}
	}
	return out
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
	base := binary.BigEndian.Uint32(ipnet.IP.To4().Mask(ipnet.Mask))
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

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
