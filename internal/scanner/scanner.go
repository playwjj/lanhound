//go:build linux

// Package scanner is LanHound's discovery engine. For each target
// interface it opens an AF_PACKET raw socket, politely ARP-sweeps the
// subnet, and also records devices overheard in other ARP traffic
// during the scan window.
//
// It only ever sends ordinary ARP requests from the host's own IP/MAC.
// No spoofing, no gratuitous ARP, no countermeasures — a sentinel,
// not a soldier.
package scanner

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"syscall"
	"time"

	"github.com/playwjj/lanhound/internal/arp"
	"github.com/playwjj/lanhound/internal/netutil"
)

// Device is one discovered host.
type Device struct {
	IP        net.IP           `json:"ip"`
	MAC       net.HardwareAddr `json:"mac"`
	Interface string           `json:"interface"`
	Via       string           `json:"via"` // "reply" (answered our request) or "heard" (overheard ARP traffic)
}

// htons converts a 16-bit protocol number to network byte order.
func htons(i uint16) uint16 { return i<<8 | i>>8 }

const (
	ethPAll        = 0x0003
	ethPArp        = 0x0806
	packetOutgoing = 4 // linux packet type: packet sent by us, seen on the way out
)

// Scan sweeps one target and returns what it found. ratePerSec paces the
// requests so a scan does not burst a whole subnet in a few milliseconds;
// the listener keeps collecting until timeout after the last send.
func Scan(t netutil.Target, timeout time.Duration, ratePerSec int) ([]Device, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("open raw socket (needs CAP_NET_RAW): %w", err)
	}
	defer syscall.Close(fd)

	ll := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: t.Iface.Index}
	if err := syscall.Bind(fd, ll); err != nil {
		return nil, fmt.Errorf("bind %s: %w", t.Iface.Name, err)
	}
	// Short receive timeout so the loop can watch its own deadline.
	tv := syscall.Timeval{Sec: 0, Usec: 200_000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("set receive timeout: %w", err)
	}

	deadline := time.Now().Add(timeout)
	sendErr := make(chan error, 1)
	go func() { sendErr <- sendRequests(fd, t, ratePerSec) }()

	found := make(map[string]*Device)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			return sortedDevices(found), fmt.Errorf("receive on %s: %w", t.Iface.Name, err)
		}
		if fromLL, ok := from.(*syscall.SockaddrLinklayer); ok && fromLL.Pkttype == packetOutgoing {
			continue // our own requests echoed back by the packet socket
		}
		pkt, ok := arp.Parse(buf[:n])
		if !ok {
			continue
		}
		if pkt.SenderIP.Equal(t.IP) || !t.Network.Contains(pkt.SenderIP) {
			continue
		}
		key := pkt.SenderIP.String()
		if _, dup := found[key]; dup {
			continue
		}
		via := "heard"
		if pkt.Op == arp.OpReply {
			via = "reply"
		}
		found[key] = &Device{IP: pkt.SenderIP, MAC: pkt.SenderMAC, Interface: t.Iface.Name, Via: via}
	}
	if err := <-sendErr; err != nil {
		return sortedDevices(found), err
	}
	return sortedDevices(found), nil
}

// sendRequests ARP-asks for every host in the target, paced by a ticker.
func sendRequests(fd int, t netutil.Target, ratePerSec int) error {
	var tick <-chan time.Time
	if ratePerSec > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(ratePerSec))
		defer ticker.Stop()
		tick = ticker.C
	}
	dst := &syscall.SockaddrLinklayer{Protocol: htons(ethPArp), Ifindex: t.Iface.Index}
	for _, host := range t.Hosts {
		frame, err := arp.BuildRequest(t.Iface.HardwareAddr, t.IP, host)
		if err != nil {
			return err
		}
		if err := syscall.Sendto(fd, frame, 0, dst); err != nil {
			return fmt.Errorf("send ARP for %s: %w", host, err)
		}
		if tick != nil {
			<-tick
		}
	}
	return nil
}

func sortedDevices(found map[string]*Device) []Device {
	out := make([]Device, 0, len(found))
	for _, d := range found {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IP.String() < out[j].IP.String()
	})
	return out
}
