// Package oui maps the first three bytes of a MAC address (the OUI)
// to the vendor name registered with the IEEE. The data file is
// generated from the official IEEE registry by scripts/update-oui.py.
package oui

import (
	_ "embed"
	"fmt"
	"net"
	"strings"
	"sync"
)

//go:embed oui_data.txt
var raw string

var (
	once  sync.Once
	table map[string]string
)

func load() {
	table = make(map[string]string, 42000)
	for _, line := range strings.Split(raw, "\n") {
		if len(line) < 8 || line[6] != '\t' {
			continue
		}
		table[line[:6]] = line[7:]
	}
}

// Lookup returns the vendor for a MAC address, or "" when unknown.
// Locally administered addresses (the second-least-significant bit of
// the first byte is set) are what phones use for MAC randomization;
// they have no vendor and Lookup says so instead of guessing.
func Lookup(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	if mac[0]&0x02 != 0 {
		return "Locally administered (likely randomized)"
	}
	once.Do(load)
	key := strings.ToUpper(fmt.Sprintf("%02x%02x%02x", mac[0], mac[1], mac[2]))
	return table[key]
}
