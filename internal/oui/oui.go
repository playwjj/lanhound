// Package oui maps a MAC address to the vendor registered with the
// IEEE. The data file holds MA-L (24-bit), MA-M (28-bit) and MA-S
// (36-bit) assignments, generated from the official registries by
// scripts/update-oui.py; the longest matching prefix wins.
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
	table = make(map[string]string, 55000)
	for _, line := range strings.Split(raw, "\n") {
		prefix, vendor, ok := strings.Cut(line, "\t")
		if !ok || vendor == "" {
			continue
		}
		table[prefix] = vendor
	}
}

// Docker is the vendor Lookup reports for Docker containers.
const Docker = "Docker container"

// IsDocker reports a MAC Docker generated for a container (02:42:…):
// what containers on macvlan or ipvlan-L2 networks show on the LAN.
// Locally administered like a phone's randomized MAC, but stable.
func IsDocker(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0] == 0x02 && mac[1] == 0x42
}

// Lookup returns the vendor for a MAC address, or "" when unknown.
// Locally administered addresses (the second-least-significant bit of
// the first byte is set) are what phones use for MAC randomization;
// they have no vendor and Lookup says so instead of guessing. Docker's
// own locally administered prefix is the exception.
func Lookup(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	if IsDocker(mac) {
		return Docker
	}
	if mac[0]&0x02 != 0 {
		return "Locally administered (likely randomized)"
	}
	once.Do(load)
	hex := strings.ToUpper(fmt.Sprintf("%x", []byte(mac)))
	for _, n := range []int{9, 7, 6} { // MA-S, MA-M, MA-L
		if v, ok := table[hex[:n]]; ok {
			return v
		}
	}
	return ""
}
