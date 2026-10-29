package probe

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestHostLabel(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 5)
	cases := map[string]string{
		"iPhone.lan.":               "iPhone",
		"nas":                       "nas",
		"192-168-1-5.isp.example.":  "",
		"host-192.168.1.5.example.": "",
		"localhost.":                "",
		"":                          "",
		"Living-Room-TV.home.arpa.": "Living-Room-TV",
	}
	for in, want := range cases {
		if got := hostLabel(in, ip); got != want {
			t.Errorf("hostLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNodeStatus(t *testing.T) {
	req := nodeStatusRequest(0x1234)
	if len(req) != 50 {
		t.Fatalf("request length %d", len(req))
	}

	// Response: header, the question name echoed, NBSTAT RR with a
	// group name first and the workstation name second.
	resp := []byte{0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0}
	resp = append(resp, req[12:46]...)
	resp = append(resp, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0)
	entry := func(name string, suffix byte, flags uint16) []byte {
		e := []byte(name)
		for len(e) < 15 {
			e = append(e, ' ')
		}
		e = append(e, suffix)
		return binary.BigEndian.AppendUint16(e, flags)
	}
	rdata := []byte{2}
	rdata = append(rdata, entry("WORKGROUP", 0x00, 0x8400)...)
	rdata = append(rdata, entry("DESKTOP-AB12", 0x00, 0x0400)...)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
	resp = append(resp, rdata...)

	if got := parseNodeStatus(resp, 0x1234); got != "DESKTOP-AB12" {
		t.Fatalf("got %q", got)
	}
	if got := parseNodeStatus(resp, 0x9999); got != "" {
		t.Fatalf("mismatched transaction id must be ignored, got %q", got)
	}
}
