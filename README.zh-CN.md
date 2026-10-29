<p align="center">
  <img src="logo/logo.svg" width="120" alt="LanHound logo">
</p>

<h1 align="center">LanHound</h1>

<p align="center">
  零配置的家庭局域网看门狗。<br>
  自动发现家里所有联网设备，记录每台设备的在线历史，
  有陌生设备接入时立刻通过 Telegram 报警。
</p>

<p align="center">
  <a href="README.md">English</a> · <b>简体中文</b>
</p>

<p align="center">
  <img src="docs/screenshot-zh.png" alt="LanHound 设备列表" width="860">
</p>

## 快速开始

```sh
docker run -d --name lanhound --restart unless-stopped \
  --network host --cap-add=NET_RAW \
  -v lanhound-data:/data \
  ghcr.io/playwjj/lanhound
```

打开 `http://<主机IP>:8686` 即可。不写配置文件、不用注册账号、没有向导：LanHound 自动识别宿主机所有内网网卡和网段，立即开始看守。

也可以用 Compose，见 [`docker-compose.yml`](docker-compose.yml)：

```sh
docker compose up -d
```

## 功能

- **整个网段一网打尽**：每 5 分钟一次礼貌的 ARP 扫描，同时常驻被动监听 DHCP、mDNS、SSDP、NetBIOS 广播。手机连上 Wi-Fi 通常一两秒内就能被发现，不必等下一轮扫描。
- **自动给设备起名**：主机名来自 DHCP、mDNS、NetBIOS 和路由器 DNS；厂商来自内置的 IEEE OUI 库（4 万多条）；型号提示（如 *Chromecast Ultra*、*DS920+*）来自 mDNS 和 UPnP。
- **新设备报警**：支持 Telegram 和任意 Webhook。报警内容包含名称、厂商、IP、MAC、首次出现时间，一眼分辨敌友。安装后的首轮扫描是静默基线，不会一上来就刷 30 条消息。
- **应对随机 MAC**：手机会对每个网络换一个 MAC。如果一台“新设备”报出的主机名和已知设备相同，LanHound 会在报警里注明，并在界面上提供一键**合并**，合并后保留所有 MAC 和完整历史。
- **在线历史**：按设备记录上线/离线时段及 IP 变更、主机名变更等事件，提供最近 7 天在线时间轴；默认保留 90 天，存在单个 SQLite 文件里。
- **实时、好用的 Web 界面**：状态实时推送，支持搜索筛选、行内改名、标记“已认识”、添加备注，手机上也能看，中英双语。
- **多网卡**：有线 + Wi-Fi 双栖、双网口小主机，每个广播域各起一个监听，设备按接口分组展示；网卡增减自动跟随。

<p align="center">
  <img src="docs/screenshot-device.png" alt="设备详情与合并提示" width="640">
  &nbsp;
  <img src="docs/screenshot-mobile.png" alt="手机界面" width="180">
</p>

## 报警配置

在 Web 界面点**设置**（⚙），填入 Telegram Bot Token（找 [@BotFather](https://t.me/BotFather) 创建）和你的 Chat ID，点**发送测试**即可。报警语言可选中文。

Webhook 会收到一个 JSON POST，字段说明见[英文 README](README.md#alerts)。其中 `text`/`content` 是渲染好的消息文本，Slack、Discord 类的入站 Webhook 可以直接用。

**国内网络访问不了 `api.telegram.org`？** 在设置里填 Bot API 反代地址，或给容器设置 `HTTPS_PROXY` 环境变量。

## 配置项

什么都不用配。少数想改默认值的用户可以用环境变量；设置了环境变量的项优先于 Web 界面，界面上会显示为锁定。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `LANHOUND_LISTEN` | `:8686` | Web 界面监听地址 |
| `LANHOUND_DATA` | `/data`（Docker）、`./data` | `lanhound.db` 所在目录 |
| `LANHOUND_SCAN_INTERVAL` | `5m` | ARP 扫描间隔（最少 `30s`） |
| `LANHOUND_INTERFACES` | 全部 | 只看守这些网卡，逗号分隔 |
| `LANHOUND_SCAN_RATE` | `300` | 每个网卡每秒最多发多少个 ARP 请求 |
| `LANHOUND_RETENTION_DAYS` | `90` | 历史保留天数 |
| `LANHOUND_PASSWORD` | — | 给界面加 HTTP Basic 密码（用户名随意） |
| `LANHOUND_LANG` | `en` | 报警语言：`en` 或 `zh` |
| `TELEGRAM_BOT_TOKEN`、`TELEGRAM_CHAT_ID` | — | Telegram 报警 |
| `TELEGRAM_API_URL` | `https://api.telegram.org` | Bot API 反代地址 |
| `LANHOUND_WEBHOOK_URL` | — | Webhook 报警 |
| `TZ` | UTC | 报警时间所用时区，如 `Asia/Shanghai` |

设备连续两轮扫描再加一分钟没有动静即判定为离线（默认约 11 分钟）。

## 支持的网络拓扑

| 拓扑 | 支持情况 |
|---|---|
| 普通家庭网络（单网段） | ✅ |
| 旁路由（同网段） | ✅ 无需任何配置：网段只按网卡地址/掩码判定，与默认网关指向谁无关 |
| 多网卡主机（有线 + Wi-Fi、双网口） | ✅ 每个网卡各一个监听 |
| 光猫 + 路由器双层 NAT（光猫在 192.168.1.0/24） | ⏳ ARP 过不了路由器；读取光猫设备表已列入计划 |
| VLAN / 访客网络 / AP 隔离 | 每个网段部署一个实例，LanHound 只能看到自己所在的广播域 |

请只在你拥有或获授权监控的网络上运行 LanHound。

## 设计原则

- **零配置**：网卡、网段、网关一律自动识别，不需要配置。
- **只当哨兵，不当打手**：LanHound 只以宿主机自己的 IP/MAC 发送普通 ARP 请求（另外对从不报名字的设备做一次反向 DNS 和 NetBIOS 名称查询），其余时间只听不说。不做 ARP 欺骗、不发免费 ARP、不踢设备下线。要拉黑请去路由器。
- **小**：单个静态二进制（纯 Go、无 cgo），界面内嵌，磁盘约 13 MB，小型网络下常驻内存约 10 MB。只需 `CAP_NET_RAW`，不需要 root，也不需要 `--privileged`。
- **数据留在家里**：无云端、无遥测、无账号。所有数据就是一个 SQLite 文件，备份迁移都方便。

## 不用 Docker

从 [Releases](https://github.com/playwjj/lanhound/releases) 下载二进制（linux amd64 / arm64 / armv7 / 386），或自行编译：

```sh
make build                              # 需要 Go 1.26+
sudo setcap cap_net_raw+ep ./lanhound   # 唯一需要的权限
./lanhound                              # Web 界面 :8686，数据在 ./data
./lanhound scan                         # 单次扫描，输出表格（-json 输出 JSON）
./lanhound -demo                        # 模拟网络，任何系统上都能体验界面
```

设备发现依赖 Linux raw socket。macOS/Windows 上请在 Linux 主机上用 Docker，或用 `-demo` 体验界面。

## 常见问题

**同一台设备出现了两次？** 多半是开启了随机 MAC 的手机。如果两条记录主机名相同，较新的那条会带“同名”标记，点开后按**合并到它**即可。也可以在设备详情里手动合并任意两台设备。

**装完之后所有设备都是“新设备”？** 正常，LanHound 不知道哪些是你家的。点一次**全部标记为已认识**，之后只有真正的新设备才会被标出（并报警）。

**有些设备一直扫不到？** 它们在另一个广播域：其他 VLAN、访客网络、二级路由后面，或被 AP 隔离。在那个网段再部署一个实例。

**能把设备踢下线吗？** 不能，这是有意的设计。请在路由器上拉黑。

## 路线图

- **v0.1（当前）**：发现引擎、在线历史、Web 界面、新设备报警
- **下一步**：安全告警组（ARP 欺骗检测、网关 MAC 变更、野 DHCP 服务器、关键设备离线）、随机 MAC 指纹识别、IPv6 设备发现、光猫/路由器设备表读取、在线热力图

## 许可证

MIT
