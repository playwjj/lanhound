// Package probe actively asks for the name of a device that has not
// introduced itself: first the LAN's DNS resolver (most home routers
// register DHCP clients in their local DNS), then the device itself via
// a NetBIOS node-status query. Both are ordinary, single unicast
// queries — nothing a router's own device list does not do.
package probe

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/passive"
)

// Name returns a hostname for ip and the source that provided it, or
// empty strings when nobody knows.
func Name(ctx context.Context, ip net.IP) (name, source string) {
	if n := reverseDNS(ctx, ip); n != "" {
		return n, passive.SrcRDNS
	}
	if n := netbiosName(ctx, ip); n != "" {
		return n, passive.SrcNBNS
	}
	return "", ""
}

func reverseDNS(ctx context.Context, ip net.IP) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return hostLabel(names[0], ip)
}

// hostLabel keeps the first label of a PTR answer ("iPhone.lan." →
// "iPhone") and rejects names synthesized from the address itself
// ("192-168-1-5.isp.example").
func hostLabel(fqdn string, ip net.IP) string {
	label, _, _ := strings.Cut(strings.TrimSuffix(fqdn, "."), ".")
	if label == "" || label == "localhost" {
		return ""
	}
	ip4 := ip.To4()
	if ip4 != nil {
		parts := make([]string, 4)
		for i, b := range ip4 {
			parts[i] = strconv.Itoa(int(b))
		}
		for _, sep := range []string{"-", ".", "_"} {
			if strings.Contains(label, strings.Join(parts, sep)) || strings.Contains(fqdn, strings.Join(parts, sep)) {
				return ""
			}
		}
	}
	return label
}

// netbiosName sends a NetBIOS node-status request (what `nmblookup -A`
// does) and returns the machine's workstation name. Windows PCs, Samba
// servers and many NAS boxes answer.
func netbiosName(ctx context.Context, ip net.IP) string {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip.String(), "137"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	id := uint16(rand.Uint32())
	if _, err := conn.Write(nodeStatusRequest(id)); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return parseNodeStatus(buf[:n], id)
}

func nodeStatusRequest(id uint16) []byte {
	b := make([]byte, 12, 50)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[4:6], 1) // one question
	// The wildcard name "*" padded with NULs, first-level encoded.
	b = append(b, 0x20, 'C', 'K')
	for i := 0; i < 15; i++ {
		b = append(b, 'A', 'A')
	}
	b = append(b, 0)
	return append(b, 0x00, 0x21, 0x00, 0x01) // NBSTAT, IN
}

func parseNodeStatus(msg []byte, id uint16) string {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[0:2]) != id || msg[2]&0x80 == 0 {
		return ""
	}
	if binary.BigEndian.Uint16(msg[6:8]) == 0 {
		return ""
	}
	off := 12
	switch {
	case off < len(msg) && msg[off] == 0x20:
		off += 34
	case off+1 < len(msg) && msg[off]&0xc0 == 0xc0:
		off += 2
	default:
		return ""
	}
	if off+10 > len(msg) || binary.BigEndian.Uint16(msg[off:off+2]) != 0x21 {
		return ""
	}
	off += 10
	if off >= len(msg) {
		return ""
	}
	count := int(msg[off])
	off++
	for i := 0; i < count && off+18 <= len(msg); i, off = i+1, off+18 {
		entry := msg[off : off+18]
		group := binary.BigEndian.Uint16(entry[16:18])&0x8000 != 0
		if entry[15] == 0x00 && !group {
			return passive.CleanNetBIOS(entry[:15])
		}
	}
	return ""
}
