<p align="center">
  <img src="logo/logo.svg" width="120" alt="LanHound logo">
</p>

<h1 align="center">LanHound</h1>

<p align="center">
  A zero-config watchdog for your home LAN.<br>
  Finds every device on your network, remembers when each one was online,
  and barks on Telegram the moment a stranger joins.
</p>

<p align="center">
  <b>English</b> · <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <img src="docs/screenshot.png" alt="LanHound device list" width="860">
</p>

## Quick start

```sh
docker run -d --name lanhound --restart unless-stopped \
  --network host --cap-add=NET_RAW \
  -v lanhound-data:/data \
  ghcr.io/playwjj/lanhound
```

Open `http://<host>:8686`. That's it: no config file, no account, no
setup wizard. LanHound finds every private subnet the host has an
interface on and starts watching.

Or with Compose — see [`docker-compose.yml`](docker-compose.yml):

```sh
docker compose up -d
```

## What it does

- **Discovers everything on the segment.** A polite ARP sweep every 5
  minutes, plus continuous passive listening to DHCP, mDNS, SSDP and
  NetBIOS chatter. A phone joining the Wi-Fi is usually seen within a
  second or two, long before the next sweep.
- **Names devices for you.** Hostnames from DHCP, mDNS, NetBIOS and your
  router's DNS; vendors from the embedded IEEE OUI registry (40k+
  entries); product hints like *Chromecast Ultra* or *DS920+* from mDNS
  and UPnP.
- **Alerts on new devices** via Telegram and/or any webhook. Each alert says
  what you need to tell friend from foe: name, vendor, IP, MAC, first-seen
  time. The first scan after install is a silent baseline, so you won't get
  30 messages in your first minute.
- **Copes with randomized MACs.** Phones rotate their MAC per network. When a
  "new" device announces the same hostname as one you already know,
  LanHound says so in the alert and offers a one-click **merge** in the UI.
  The merged device keeps every MAC and its full history.
- **Keeps history.** Online/offline sessions and events (IP changes,
  hostname changes) per device, with a 7-day presence timeline, kept for 90
  days in a single SQLite file.
- **A live, friendly web UI.** Updates stream in real time. Search and
  filter, rename inline, mark devices as known, add notes. It works on a
  phone, in English and 中文.
- **Multi-interface.** Wired + Wi-Fi or dual-NIC hosts get one watcher
  per broadcast domain, and devices are grouped by interface. Interfaces
  that come and go are followed automatically.

<p align="center">
  <img src="docs/screenshot-device.png" alt="Device details with merge suggestion" width="640">
  &nbsp;
  <img src="docs/screenshot-mobile.png" alt="Mobile view" width="180">
</p>

## Alerts

Open **Settings** (⚙) in the web UI, paste a Telegram bot token
(from [@BotFather](https://t.me/BotFather)) and your chat ID, and press
**Send test**. A webhook receives a JSON POST:

```json
{
  "event": "new_device",
  "devices": [{ "id": 17, "hostname": "android-4f2a9c", "vendor": "Liteon Technology Corporation",
                "ip": "192.168.2.77", "mac": "94:e9:79:ab:cd:10", "interface": "eth0",
                "firstSeen": "2026-10-29T09:50:18+08:00", "randomized": false }],
  "text": "🐕 New device on your network …",
  "content": "🐕 New device on your network …"
}
```

`text`/`content` carry the rendered message, so Slack- and Discord-style
incoming webhooks work as-is. If `api.telegram.org` is unreachable from
your network, set a Bot API proxy URL in Settings, or set `HTTPS_PROXY`.

## Configuration

None required. For the few who want to override something, everything is
an environment variable. Variables that are set win over the web UI, and
the UI shows them as locked.

| Variable | Default | Meaning |
|---|---|---|
| `LANHOUND_LISTEN` | `:8686` | Web UI address |
| `LANHOUND_DATA` | `/data` (Docker), `./data` | Where `lanhound.db` lives |
| `LANHOUND_SCAN_INTERVAL` | `5m` | Time between ARP sweeps (min `30s`) |
| `LANHOUND_INTERFACES` | all | Comma-separated interfaces to watch |
| `LANHOUND_SCAN_RATE` | `300` | Max ARP requests per second per interface |
| `LANHOUND_RETENTION_DAYS` | `90` | History retention |
| `LANHOUND_PASSWORD` | — | Protect the UI with HTTP basic auth (any username) |
| `LANHOUND_LANG` | `en` | Alert language: `en` or `zh` |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | Telegram alerts |
| `TELEGRAM_API_URL` | `https://api.telegram.org` | Bot API proxy |
| `LANHOUND_WEBHOOK_URL` | — | Webhook alerts |
| `TZ` | UTC | Time zone for alert timestamps |

A device counts as offline once it has been silent for two sweeps plus a
minute (about 11 minutes by default).

## Networks it understands

| Topology | Support |
|---|---|
| Flat home LAN (single subnet) | ✅ |
| Bypass router / 旁路由 (same subnet) | ✅ nothing to configure: discovery reads each interface's own address/mask, not the default route |
| Multi-homed host (wired + Wi-Fi, dual NIC) | ✅ one watcher per interface |
| ISP modem + router double NAT (modem on 192.168.1.0/24) | ⏳ ARP can't cross a router; reading the modem's device table is planned |
| VLANs / guest networks / AP isolation | one instance per segment. LanHound only sees its own broadcast domain |

Only run LanHound on networks you own or are authorized to monitor.

## Design principles

- **Zero configuration.** Interfaces, subnets and gateways are detected,
  never configured.
- **Sentinel, not soldier.** LanHound sends only ordinary ARP requests
  from the host's own IP/MAC (plus a reverse-DNS lookup and a NetBIOS name
  query for devices that never said their name) and otherwise listens. No
  ARP spoofing, no gratuitous ARP, no deauth, no "kicking" devices.
  Enforcement belongs to your router.
- **Small.** One static binary (pure Go, no cgo) with the UI embedded.
  About 13 MB on disk, and around 10 MB of RAM watching a small network.
  Needs only `CAP_NET_RAW`, not root or `--privileged`.
- **Your data stays home.** No cloud, no telemetry, no account. One SQLite
  file you can back up or move.

## Without Docker

Download a binary from [Releases](https://github.com/playwjj/lanhound/releases)
(linux amd64 / arm64 / armv7 / 386), or build it:

```sh
make build                              # needs Go 1.26+
sudo setcap cap_net_raw+ep ./lanhound   # the only privilege it needs
./lanhound                              # web UI on :8686, data in ./data
./lanhound scan                         # one-shot scan, print a table (-json for JSON)
./lanhound -demo                        # simulated network: try the UI on any OS
```

Discovery uses Linux raw sockets. On macOS or Windows, use Docker on a
Linux host, or `-demo` to explore the UI.

### Hacking on the UI

The Vue 3 front end lives in `web/` and builds into `internal/web/dist`,
which is embedded into the binary (and committed, so `go build` works
without Node):

```sh
./lanhound -demo &          # API on :8686 with fake devices
cd web && npm ci && npm run dev
make web                    # rebuild the embedded dist before committing
```

## FAQ

**A device shows up twice.** It is probably a phone using a randomized MAC.
If both entries share a hostname, LanHound marks the newer one with *same
name*. Open it and press **Merge into it**. You can also merge any two
devices by hand from the device panel.

**I installed it and everything is "New".** Expected: LanHound can't know
which devices are yours. Press **Mark all as known** once; from then on
only genuinely new devices stand out (and alert).

**Some devices on my network never appear.** They are on a different
broadcast domain: another VLAN, a guest network, behind a second router, or
isolated by the access point. Run another instance there.

**Can it block a device?** No, by design. Block it on your router.

## Roadmap

- **v0.1 (this)**: discovery engine, history, web UI, new-device alerts
- **Next**: security alerts (ARP-spoof detection, gateway MAC change,
  rogue DHCP server, critical device offline), randomized-MAC
  fingerprinting, IPv6 discovery, modem/router device-table import, presence
  heat maps

## License

MIT
