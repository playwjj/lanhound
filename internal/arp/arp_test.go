package arp

import (
	"bytes"
	"net"
	"testing"
)

func TestBuildParseRoundTrip(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcIP := net.ParseIP("192.168.2.10")
	tgtIP := net.ParseIP("192.168.2.1")

	frame, err := BuildRequest(srcMAC, srcIP, tgtIP)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if len(frame) != 42 {
		t.Fatalf("frame length = %d, want 42", len(frame))
	}
	for i := 0; i < 6; i++ {
		if frame[i] != 0xff {
			t.Fatalf("destination not broadcast at byte %d", i)
		}
	}

	pkt, ok := Parse(frame)
	if !ok {
		t.Fatal("Parse rejected a frame BuildRequest produced")
	}
	if pkt.Op != OpRequest {
		t.Errorf("Op = %d, want %d", pkt.Op, OpRequest)
	}
	if !bytes.Equal([]byte(pkt.SenderMAC), []byte(srcMAC)) {
		t.Errorf("SenderMAC = %v, want %v", pkt.SenderMAC, srcMAC)
	}
	if !pkt.SenderIP.Equal(srcIP) {
		t.Errorf("SenderIP = %v, want %v", pkt.SenderIP, srcIP)
	}
	if !pkt.TargetIP.Equal(tgtIP) {
		t.Errorf("TargetIP = %v, want %v", pkt.TargetIP, tgtIP)
	}
}

func TestParseReply(t *testing.T) {
	// Hand-built reply frame: aa:bb:cc:dd:ee:ff / 192.168.2.1 answers us.
	frame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst = us
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src = responder
		0x08, 0x06, // ARP
		0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02, // op = reply
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // sender MAC
		192, 168, 2, 1, // sender IP
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // target MAC
		192, 168, 2, 10, // target IP
	}
	pkt, ok := Parse(frame)
	if !ok {
		t.Fatal("Parse rejected a valid reply frame")
	}
	if pkt.Op != OpReply {
		t.Errorf("Op = %d, want %d", pkt.Op, OpReply)
	}
	if pkt.SenderMAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("SenderMAC = %v", pkt.SenderMAC)
	}
	if pkt.SenderIP.String() != "192.168.2.1" {
		t.Errorf("SenderIP = %v", pkt.SenderIP)
	}
}

func TestParseRejectsNonARP(t *testing.T) {
	frame := make([]byte, 60)
	frame[12], frame[13] = 0x08, 0x00 // IPv4 EtherType
	if _, ok := Parse(frame); ok {
		t.Error("Parse accepted an IPv4 frame as ARP")
	}
	if _, ok := Parse(make([]byte, 10)); ok {
		t.Error("Parse accepted a truncated frame")
	}
}

func TestBuildRequestRejectsBadInput(t *testing.T) {
	if _, err := BuildRequest(net.HardwareAddr{1, 2, 3}, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")); err == nil {
		t.Error("expected error for short MAC")
	}
	if _, err := BuildRequest(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.ParseIP("::1"), net.ParseIP("10.0.0.2")); err == nil {
		t.Error("expected error for IPv6 source")
	}
}
