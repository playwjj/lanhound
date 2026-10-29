package netutil

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Gateways returns the IPv4 default gateway(s) of each interface, read
// from the kernel routing table. Whatever box the default route points
// at — main router or bypass router (旁路由) — is "the gateway" whose MAC
// the security checks watch. Empty on non-Linux systems.
func Gateways() map[string][]net.IP {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseRoutes(f)
}

const rtfGateway = 0x2

func parseRoutes(r io.Reader) map[string][]net.IP {
	out := map[string][]net.IP{}
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" { // default routes only
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfGateway == 0 {
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || gw == 0 {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(gw)) // printed in host byte order
		dup := false
		for _, g := range out[f[0]] {
			dup = dup || g.Equal(ip)
		}
		if !dup {
			out[f[0]] = append(out[f[0]], ip)
		}
	}
	return out
}
