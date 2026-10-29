package scanner

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/lanhound/internal/arp"
	"github.com/playwjj/lanhound/internal/netutil"
	"github.com/playwjj/lanhound/internal/passive"
)

// fakeLAN answers ARP requests for the hosts in macs, like a real
// broadcast domain would.
type fakeLAN struct {
	mu     sync.Mutex
	macs   map[string]net.HardwareAddr
	queue  chan []byte
	closed bool
}

func newFakeLAN(hosts map[string]net.HardwareAddr) *fakeLAN {
	return &fakeLAN{macs: hosts, queue: make(chan []byte, 1024)}
}

func (f *fakeLAN) Read(buf []byte) (int, bool, error) {
	select {
	case fr := <-f.queue:
		return copy(buf, fr), false, nil
	case <-time.After(20 * time.Millisecond):
		return 0, false, errTimeout
	}
}

func (f *fakeLAN) Write(frame []byte) error {
	pkt, ok := arp.Parse(frame)
	if !ok {
		return nil
	}
	f.mu.Lock()
	mac, ok := f.macs[pkt.TargetIP.String()]
	f.mu.Unlock()
	if !ok {
		return nil
	}
	reply, _ := arp.BuildRequest(mac, pkt.TargetIP, pkt.SenderIP)
	reply[14+7] = arp.OpReply
	f.queue <- reply
	return nil
}

func (f *fakeLAN) Close() error { f.closed = true; return nil }

func testTarget() netutil.Target {
	_, n, _ := net.ParseCIDR("10.9.0.0/29")
	self := net.IPv4(10, 9, 0, 1).To4()
	t := netutil.Target{
		Iface:   net.Interface{Index: 7, Name: "eth9", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}},
		IP:      self,
		Network: n,
	}
	for i := 2; i < 7; i++ {
		t.Hosts = append(t.Hosts, net.IPv4(10, 9, 0, byte(i)).To4())
	}
	return t
}

func TestEngineSweepAndFirstRound(t *testing.T) {
	lan := newFakeLAN(map[string]net.HardwareAddr{
		"10.9.0.3": {0x24, 0x0a, 0xc4, 0, 0, 3},
		"10.9.0.5": {0x24, 0x0a, 0xc4, 0, 0, 5},
	})
	openLinkFunc = func(net.Interface) (link, error) { return lan, nil }
	targetsFunc = func() ([]netutil.Target, []string) { return []netutil.Target{testTarget()}, nil }
	defer func() { openLinkFunc, targetsFunc = openLink, netutil.Targets }()

	var mu sync.Mutex
	got := map[string]string{}
	e := New(Config{Rate: 1000, Window: 50 * time.Millisecond, Interval: time.Hour, OnSighting: func(s passive.Sighting) {
		mu.Lock()
		got[s.MAC.String()] = s.IP.String() + " " + s.Iface + " " + s.Source
		mu.Unlock()
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	select {
	case <-e.FirstRound():
	case <-time.After(3 * time.Second):
		t.Fatal("first round never completed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got["24:0a:c4:00:00:03"] != "10.9.0.3 eth9 arp-reply" {
		t.Fatalf("got %v", got)
	}
	st := e.Status()
	if len(st) != 1 || st[0].LastReplies != 2 || st[0].Sweeping || st[0].LastSweep.IsZero() {
		t.Fatalf("status %+v", st)
	}
}

func TestWorkerAccept(t *testing.T) {
	w := newWorker(testTarget(), Config{})
	cases := []struct {
		s      passive.Sighting
		ok     bool
		keepIP bool
	}{
		{passive.Sighting{MAC: net.HardwareAddr{0x24, 0, 0, 0, 0, 9}, IP: net.IPv4(10, 9, 0, 4)}, true, true},
		{passive.Sighting{MAC: net.HardwareAddr{0x24, 0, 0, 0, 0, 9}, IP: net.IPv4(172, 16, 0, 4)}, true, false},
		{passive.Sighting{MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, IP: net.IPv4(10, 9, 0, 4)}, false, false},    // our own MAC
		{passive.Sighting{MAC: net.HardwareAddr{0x24, 0, 0, 0, 0, 9}, IP: net.IPv4(10, 9, 0, 1)}, false, false}, // our own IP
		{passive.Sighting{MAC: net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 9}}, false, false},
		{passive.Sighting{MAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}}, false, false},
	}
	for i, c := range cases {
		ok := w.accept(&c.s)
		if ok != c.ok || (ok && (c.s.IP != nil) != c.keepIP) {
			t.Errorf("case %d: ok=%v ip=%v", i, ok, c.s.IP)
		}
	}
}
