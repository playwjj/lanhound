//go:build linux

package scanner

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const ethPAll = 0x0003

// Multicast groups the NIC must accept for passive listening, as
// Ethernet addresses: mDNS 224.0.0.251 and SSDP 239.255.255.250.
var multicastMACs = []net.HardwareAddr{
	{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb},
	{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa},
}

func htons(i uint16) uint16 { return i<<8 | i>>8 }

// rawLink is an AF_PACKET socket bound to one interface. Opening it is
// the only thing in LanHound that needs CAP_NET_RAW.
type rawLink struct {
	fd      int
	ifindex int
}

func openLink(iface net.Interface) (link, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("open raw socket (needs CAP_NET_RAW): %w", err)
	}
	l := &rawLink{fd: fd, ifindex: iface.Index}
	if err := l.setup(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("%s: %w", iface.Name, err)
	}
	return l, nil
}

func (l *rawLink) setup() error {
	raw, err := bpf.Assemble(filter())
	if err != nil {
		return fmt.Errorf("assemble filter: %w", err)
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0]))}
	if err := unix.SetsockoptSockFprog(l.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return fmt.Errorf("attach filter: %w", err)
	}
	if err := unix.Bind(l.fd, &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: l.ifindex}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	for _, mac := range multicastMACs {
		mreq := unix.PacketMreq{Ifindex: int32(l.ifindex), Type: unix.PACKET_MR_MULTICAST, Alen: 6}
		copy(mreq.Address[:], mac)
		// Best effort: without it we still hear broadcasts (ARP, DHCP, NBNS).
		_ = unix.SetsockoptPacketMreq(l.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	}
	// A short receive timeout lets the read loop notice shutdown.
	tv := unix.Timeval{Sec: 0, Usec: 500_000}
	return unix.SetsockoptTimeval(l.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}

func (l *rawLink) Read(buf []byte) (int, bool, error) {
	n, from, err := unix.Recvfrom(l.fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, false, errTimeout
		}
		return 0, false, err
	}
	outgoing := false
	if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
		outgoing = true
	}
	return n, outgoing, nil
}

func (l *rawLink) Write(frame []byte) error {
	return unix.Sendto(l.fd, frame, 0, &unix.SockaddrLinklayer{Protocol: htons(0x0806), Ifindex: l.ifindex})
}

func (l *rawLink) Close() error { return unix.Close(l.fd) }
