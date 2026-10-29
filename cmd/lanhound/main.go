// LanHound P0: scan the local network(s) and print the devices found.
//
// Zero configuration: run it and it scans every private subnet the
// host has an interface on. It needs CAP_NET_RAW (root, or
// `sudo setcap cap_net_raw+ep ./lanhound`), or use the Docker image
// with --network host --cap-add=NET_RAW.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"github.com/playwjj/lanhound/internal/netutil"
	"github.com/playwjj/lanhound/internal/oui"
	"github.com/playwjj/lanhound/internal/scanner"
)

type row struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Via       string `json:"via"`
}

func main() {
	ifaceName := flag.String("iface", "", "only scan this interface (default: all private subnets)")
	timeout := flag.Duration("timeout", 6*time.Second, "listen window per interface")
	rate := flag.Int("rate", 300, "max ARP requests per second per interface")
	asJSON := flag.Bool("json", false, "print results as JSON")
	flag.Parse()

	targets, skipped := netutil.Targets()
	for _, s := range skipped {
		fmt.Fprintln(os.Stderr, "note:", s)
	}
	var rows []row
	for _, t := range targets {
		if *ifaceName != "" && t.Iface.Name != *ifaceName {
			continue
		}
		if !*asJSON {
			fmt.Printf("== %s  %s  (%d hosts) ==\n", t.Iface.Name, t.Network, len(t.Hosts))
		}
		devices, err := scanner.Scan(t, *timeout, *rate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", t.Iface.Name, err)
			continue
		}
		for _, d := range devices {
			rows = append(rows, row{
				Interface: d.Interface,
				IP:        d.IP.String(),
				MAC:       d.MAC.String(),
				Vendor:    oui.Lookup(d.MAC),
				Via:       d.Via,
			})
		}
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no private IPv4 interface found to scan")
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if rows == nil {
			rows = []row{}
		}
		_ = enc.Encode(rows)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tMAC\tVENDOR\tVIA")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.IP, r.MAC, vendorOrDash(r.Vendor), r.Via)
	}
	_ = w.Flush()
	fmt.Printf("%d device(s) found\n", len(rows))
}

func vendorOrDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

var _ = net.IPv4len // keep net import if flags change; harmless
