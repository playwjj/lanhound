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
	hex := strings.ToUpper(fmt.Sprintf("%x", []byte(mac)))
	for _, n := range []int{9, 7, 6} { // MA-S, MA-M, MA-L
		if v, ok := table[hex[:n]]; ok {
			return v
		}
	}
	return ""
}
