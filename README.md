<p align="center">
  <img src="logo/logo.svg" width="120" alt="LanHound logo">
</p>

<h1 align="center">LanHound</h1>

<p align="center">
  A zero-config watchdog for your home LAN.<br>
  Discovers every device on your network, remembers when each one first showed up,
  and (soon) barks on Telegram when a stranger joins.
</p>

> **Status: P0 skeleton.** The ARP discovery engine works and prints a device
> list. Storage, the web UI and alerts are on the roadmap below — expect
> breaking changes until v0.1.0.

## Why

Your home network has more devices than you think — phones, TVs, cameras,
plugs, boxes you forgot about. Your router's device list only shows what
went through *it*, keeps no history, and dies with the router brand.
LanHound sits anywhere on the segment, watches the whole broadcast domain
regardless of which box handed out the IP, and keeps the records on
*your* disk.

## Quick start

```sh
docker run --rm --network host --cap-add=NET_RAW ghcr.io/playwjj/lanhound
```

That's it. No config file, no account. LanHound finds every private
subnet the host has an interface on — wired + Wi-Fi, multi-homed hosts
included — sweeps it politely with ordinary ARP requests, and prints:

```
== eth0  192.168.2.0/24  (253 hosts) ==
IP              MAC                VENDOR                    VIA
192.168.2.1     8c:3b:ad:xx:xx:xx  HUAWEI TECHNOLOGIES CO.   reply
192.168.2.31    d4:a6:51:xx:xx:xx  Samsung Electronics       reply
192.168.2.87    24:0a:c4:xx:xx:xx  Espressif Inc.            heard
3 device(s) found
```

Vendor names come from the official IEEE OUI registry, embedded in the
binary (40k+ entries). MAC addresses with the locally-administered bit
set are reported as `Locally administered (likely randomized)` instead
of a made-up vendor — that's your phone doing MAC randomization.

### Build from source

```sh
go build -o lanhound ./cmd/lanhound
sudo setcap cap_net_raw+ep ./lanhound   # the only privilege ARP needs
./lanhound          # table output
./lanhound -json    # machine-readable
```

Flags: `-iface eth0` (scan one interface), `-timeout 6s` (listen window),
`-rate 300` (max ARP requests/second — a scan should never burst a subnet).

## Design principles

- **Zero configuration.** Interfaces, subnets and gateways are detected,
  never configured. The default route pointing at a bypass router
  (旁路由) changes nothing: discovery is layer-2 and reads each
  interface's own address/mask.
- **Sentinel, not soldier.** LanHound sends only ordinary ARP requests
  from the host's own IP/MAC and otherwise listens. No ARP spoofing, no
  gratuitous ARP, no deauth, no "kicking" devices. Enforcement belongs
  to your router; LanHound reports.
- **Single static binary.** Pure Go, no cgo, ~5 MB. Runs on a NAS, a
  Raspberry Pi, an OpenWrt box, or any always-on Linux host.
- **Your data stays home.** No cloud, no telemetry, no account.

## Networks it understands

| Topology | Support |
|---|---|
| Flat home LAN (single subnet) | ✅ |
| Bypass router / 旁路由 (same subnet) | ✅ nothing to configure |
| Multi-homed host (wired + Wi-Fi, dual NIC) | ✅ one sweep per interface |
| ISP modem + router double NAT (e.g. modem on 192.168.1.0/24) | ⏳ phase 2 reads the modem's device table; ARP alone can't cross the router |
| VLAN-segmented / corporate networks | one instance per segment; only run it on networks you own or are authorized to monitor |

## Roadmap

- **P0 (this)** — ARP + passive discovery engine, multi-interface, CLI list
- **P1** — SQLite presence history, Vue web UI (live device list, naming, whitelists)
- **P2** — new-device alerts (Telegram/Webhook), security alert pack
  (ARP-spoof detection, gateway-MAC change, rogue DHCP server, critical
  device offline), randomized-MAC fingerprinting, IPv6 discovery,
  modem/router device-table import

## License

MIT
