package core

import (
	"regexp"
	"strings"
	"time"

	"github.com/playwjj/lanhound/internal/services"
	"github.com/playwjj/lanhound/internal/store"
)

// Link is how a device is connected, as the UI shows it. LanHound sees
// Ethernet frames either way, so it is only certain when a router
// reports the Wi-Fi association or the user set it; otherwise it
// guesses from clues.
type Link struct {
	Type    string   `json:"type"`              // "wifi" or "wired"
	Certain bool     `json:"certain"`           // reported by a router, or set by the user
	Manual  bool     `json:"manual,omitempty"`  // set by the user
	Band    string   `json:"band,omitempty"`    // certain only
	Signal  int      `json:"signal,omitempty"`  // dBm, certain only
	Via     string   `json:"via,omitempty"`     // router label, certain only
	Reasons []string `json:"reasons,omitempty"` // random-mac | wifi-chip | phone | router | nas
}

// wifiStale: a router report older than this no longer counts (the
// device may have left, or moved to a cable).
const wifiStale = 10 * time.Minute

// wifiVendor matches makers whose network parts are (nearly) only Wi-Fi:
// IoT modules and Wi-Fi card/module makers. Deliberately short — vendors
// making both (Realtek, Intel, Apple…) say nothing.
var wifiVendor = regexp.MustCompile(`(?i)espressif|tuya|azurewave|murata|bilian|gaoshengda|hui zhou|universal global scientific|` +
	`dreame|roborock|ecovacs|yeelink|xiaomi electronics|beijing xiaomi mobile|tmall|xiaodu|amazon technologies|sonos|shelly|itead`)

// phoneName: iOS names devices "<Owner>s-iPhone"; Android brands put the
// model first.
var phoneName = regexp.MustCompile(`(?i)iphone|ipad|^(galaxy|android|redmi|pixel|oneplus|huawei-|honor-|oppo|vivo)`)

// link derives a device's connection.
func link(d *store.Device, now time.Time) *Link {
	if w := d.WiFi; w != nil && now.Sub(w.At) < wifiStale {
		return &Link{Type: "wifi", Certain: true, Band: w.Band, Signal: w.Signal, Via: w.Router}
	}
	if d.LinkType != "" {
		return &Link{Type: d.LinkType, Certain: true, Manual: true}
	}
	var wifi []string
	if randomized(d.MAC) {
		wifi = append(wifi, "random-mac") // phones and laptops randomize on Wi-Fi only
	}
	if wifiVendor.MatchString(d.Vendor) {
		wifi = append(wifi, "wifi-chip")
	}
	if d.Kind == services.KindPhone || phoneName.MatchString(d.Hostname) || strings.HasPrefix(strings.ToLower(vendorClass(d.DHCPFP)), "android-dhcp") {
		wifi = append(wifi, "phone")
	}
	if len(wifi) > 0 {
		return &Link{Type: "wifi", Reasons: wifi}
	}
	switch d.Kind {
	case services.KindRouter:
		return &Link{Type: "wired", Reasons: []string{"router"}}
	case services.KindNAS:
		return &Link{Type: "wired", Reasons: []string{"nas"}}
	}
	return nil
}

// vendorClass is the option-60 half of a DHCP fingerprint.
func vendorClass(fp string) string {
	_, vc, _ := strings.Cut(fp, "|")
	return vc
}
