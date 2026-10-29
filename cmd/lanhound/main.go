// LanHound: a zero-config watchdog for your home LAN.
//
//	lanhound            run the watchdog and web UI (default)
//	lanhound scan       one-shot scan, print the devices and exit
//	lanhound probe IP   show which common services a host runs
//	lanhound version    print the version
//
// Discovery needs CAP_NET_RAW (root, or `sudo setcap cap_net_raw+ep
// ./lanhound`), or use the Docker image with --network host
// --cap-add=NET_RAW. Nothing needs configuring; the few knobs that
// exist are environment variables (see README).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	_ "time/tzdata" // honour TZ in the scratch-based Docker image

	"github.com/playwjj/lanhound/internal/core"
	"github.com/playwjj/lanhound/internal/demo"
	"github.com/playwjj/lanhound/internal/hass"
	"github.com/playwjj/lanhound/internal/netutil"
	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/oui"
	"github.com/playwjj/lanhound/internal/passive"
	"github.com/playwjj/lanhound/internal/probe"
	"github.com/playwjj/lanhound/internal/scanner"
	"github.com/playwjj/lanhound/internal/security"
	"github.com/playwjj/lanhound/internal/services"
	"github.com/playwjj/lanhound/internal/store"
	"github.com/playwjj/lanhound/internal/web"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		serve(args)
	case "scan":
		scan(args)
	case "probe":
		probeCmd(args)
	case "version":
		fmt.Println("lanhound", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (want serve, scan, probe or version)\n", cmd)
		os.Exit(2)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, f)
	}
	return out
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", env("LANHOUND_LISTEN", ":8686"), "web UI address (env LANHOUND_LISTEN)")
	dataDir := fs.String("data", env("LANHOUND_DATA", "data"), "directory for lanhound.db (env LANHOUND_DATA)")
	interval := fs.Duration("interval", envDuration("LANHOUND_SCAN_INTERVAL", 5*time.Minute), "time between ARP sweeps (env LANHOUND_SCAN_INTERVAL)")
	ifaces := fs.String("iface", env("LANHOUND_INTERFACES", ""), "comma-separated interfaces to watch; default all (env LANHOUND_INTERFACES)")
	rate := fs.Int("rate", envInt("LANHOUND_SCAN_RATE", 300), "max ARP requests per second per interface (env LANHOUND_SCAN_RATE)")
	retention := fs.Int("retention", envInt("LANHOUND_RETENTION_DAYS", 90), "days of history to keep (env LANHOUND_RETENTION_DAYS)")
	dhcpProbe := fs.String("dhcp-probe", env("LANHOUND_DHCP_PROBE", "30m"), "how often to broadcast a DHCPDISCOVER to find rogue DHCP servers, or \"off\" (env LANHOUND_DHCP_PROBE)")
	demoMode := fs.Bool("demo", false, "simulate a home network instead of scanning (for trying the UI)")
	_ = fs.Parse(args)

	probeEvery := -time.Duration(1)
	if *dhcpProbe != "off" && *dhcpProbe != "0" {
		d, err := time.ParseDuration(*dhcpProbe)
		if err != nil || d < time.Minute {
			log.Fatal("LANHOUND_DHCP_PROBE must be a duration of at least 1m, or \"off\"")
		}
		probeEvery = d
	}
	if *interval < 30*time.Second {
		log.Fatal("scan interval must be at least 30s")
	}
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatal(err)
	}
	dbName := "lanhound.db"
	if *demoMode {
		dbName = "lanhound-demo.db"
	}
	st, err := store.Open(filepath.Join(*dataDir, dbName))
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	settings, err := core.NewSettings(st, notify.Settings{
		Language:       os.Getenv("LANHOUND_LANG"),
		TelegramToken:  os.Getenv("TELEGRAM_BOT_TOKEN"),
		TelegramChatID: os.Getenv("TELEGRAM_CHAT_ID"),
		TelegramAPI:    os.Getenv("TELEGRAM_API_URL"),
		WebhookURL:     os.Getenv("LANHOUND_WEBHOOK_URL"),
	})
	if err != nil {
		log.Fatalf("load settings: %v", err)
	}

	const window = 6 * time.Second
	hub := core.NewHub()
	opts := core.Options{
		Store:        st,
		Hub:          hub,
		Settings:     settings,
		OfflineAfter: 2**interval + window + time.Minute,
		Retention:    time.Duration(*retention) * 24 * time.Hour,
		Resolve:      probe.Name,
	}
	if *demoMode {
		opts.OfflineAfter, opts.Resolve = 35*time.Second, nil
	}
	reg, err := core.NewRegistry(opts)
	if err != nil {
		log.Fatalf("load devices: %v", err)
	}

	guard := security.New(st, reg.RaiseFinding)
	observe := func(s passive.Sighting) {
		reg.Observe(s)
		guard.Observe(s)
	}
	routers, err := core.NewRouters(st, reg, hub)
	if err != nil {
		log.Fatalf("load router sources: %v", err)
	}
	bridge, err := hass.New(st, reg, hub, func() string { return settings.Get().Language }, version, os.Getenv("LANHOUND_MQTT_URL"))
	if err != nil {
		log.Fatalf("load Home Assistant settings: %v", err)
	}
	svcScan, err := core.NewServiceScan(st, reg, func(ip string) bool {
		for _, gws := range guard.Gateways() {
			for _, g := range gws {
				if g == ip {
					return true
				}
			}
		}
		return false
	})
	if err != nil {
		log.Fatalf("load service scan settings: %v", err)
	}
	srv := &web.Server{Registry: reg, Settings: settings, Hub: hub, Security: guard, Routers: routers, HASS: bridge, Services: svcScan, Version: version, Interval: *interval, Password: os.Getenv("LANHOUND_PASSWORD")}
	publishStatus := func() { hub.Publish("status", srv.Status()) }

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var firstRound <-chan struct{}
	if *demoMode {
		d := demo.New(observe, publishStatus)
		guard.SetGateways(demo.Gateways())
		srv.Scanner, srv.Interval, firstRound = d, 10*time.Second, d.FirstRound()
		go d.Run(ctx)
		log.Print("demo mode: simulating a home network, nothing is scanned")
	} else {
		eng := scanner.New(scanner.Config{
			Interval:       *interval,
			Window:         window,
			Rate:           *rate,
			Only:           splitList(*ifaces),
			DHCPProbeEvery: probeEvery,
			OnSighting:     observe,
			OnStatus:       publishStatus,
		})
		srv.Scanner, firstRound = eng, eng.FirstRound()
		go eng.Run(ctx)
		go guard.Run(ctx)
		for _, s := range eng.Skipped() {
			log.Print("note: ", s)
		}
	}
	go func() {
		select {
		case <-firstRound:
			reg.EndBaseline()
			publishStatus()
			// Router tables only after our own first sweep, so devices on
			// the local wire are claimed by their real interface first.
			go routers.Run(ctx)
		case <-ctx.Done():
		}
	}()
	go reg.Run(ctx)
	go bridge.Run(ctx)
	go svcScan.Run(ctx)

	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	log.Printf("LanHound %s: web UI on %s, data in %s", version, displayAddr(*listen), *dataDir)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	reg.Flush()
}

func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "http://<this-host>" + listen
	}
	return "http://" + listen
}

type row struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Hostname  string `json:"hostname"`
	Via       string `json:"via"`
}

// scan is the one-shot command-line scan.
func scan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	ifaceName := fs.String("iface", "", "only scan this interface (default: all private subnets)")
	timeout := fs.Duration("timeout", 6*time.Second, "listen window after the last request")
	rate := fs.Int("rate", 300, "max ARP requests per second per interface")
	asJSON := fs.Bool("json", false, "print results as JSON")
	_ = fs.Parse(args)

	var include []string
	if *ifaceName != "" {
		include = []string{*ifaceName}
	}
	targets, skipped := netutil.Targets(include)
	for _, s := range skipped {
		fmt.Fprintln(os.Stderr, "note:", s)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no private IPv4 interface found to scan")
		os.Exit(1)
	}
	rows := []row{}
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
		}
		for _, d := range devices {
			rows = append(rows, row{
				Interface: d.Interface,
				IP:        d.IP.String(),
				MAC:       d.MAC.String(),
				Vendor:    oui.Lookup(d.MAC),
				Hostname:  d.Hostname,
				Via:       d.Via,
			})
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tMAC\tVENDOR\tHOSTNAME\tVIA")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.IP, r.MAC, dash(r.Vendor), dash(r.Hostname), r.Via)
	}
	_ = w.Flush()
	fmt.Printf("%d device(s) found\n", len(rows))
}

// probeCmd prints the services of one or more hosts — the same probe
// the optional background service scan runs.
func probeCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: lanhound probe <ip> [ip…]")
		os.Exit(2)
	}
	for _, ip := range args {
		svcs := services.Prober{}.Probe(context.Background(), ip)
		fmt.Printf("== %s  %s ==\n", ip, dash(services.Classify(svcs, services.Hints{})))
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		for _, s := range svcs {
			risky := ""
			if s.Risky {
				risky = "  ⚠ risky"
			}
			fmt.Fprintf(w, "%d\t%s\t%s%s\n", s.Port, s.Name, s.Detail, risky)
		}
		_ = w.Flush()
		if len(svcs) == 0 {
			fmt.Println("no open ports among", len(services.DefaultPorts), "probed")
		}
	}
}

func dash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}
