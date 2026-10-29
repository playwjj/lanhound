package oui

import (
	"net"
	"testing"
)

func TestLookupLongestPrefix(t *testing.T) {
	cases := map[string]string{
		"a0:c5:f2:b5:85:56": "Oray.com co., LTD.",    // MA-M block inside an IEEE-RA MA-L
		"00:11:32:aa:bb:02": "Synology Incorporated", // plain MA-L
		"da:a1:19:00:00:02": "Locally administered (likely randomized)",
		"02:42:c0:a8:02:ca": Docker,
		"02:43:c0:a8:02:ca": "Locally administered (likely randomized)",
		"00:00:00:00:00:00": "XEROX CORPORATION",
	}
	for mac, want := range cases {
		hw, _ := net.ParseMAC(mac)
		if got := Lookup(hw); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", mac, got, want)
		}
	}
	// An MA-S assignment (36-bit) must beat its MA-L parent.
	hw, _ := net.ParseMAC("8c:1f:64:00:00:01")
	if got := Lookup(hw); got == "" || got == "IEEE Registration Authority" {
		t.Errorf("MA-S lookup fell back to parent: %q", got)
	}
}
