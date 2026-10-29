package notify

import (
	"fmt"
	"strings"
	"time"
)

// maxListed caps how many devices one message spells out.
const maxListed = 10

var texts = map[string]map[string]string{
	"en": {
		"new1":       "🐕 New device on your network",
		"newN":       "🐕 %d new devices on your network",
		"test":       "🐕 LanHound test message — notifications work.",
		"conflict":   "🚨 IP address conflict: %s",
		"conflictGw": "🚨 Possible ARP spoofing of your gateway %s",
		"conflictTx": "Two devices are claiming the same IP address at the same time. If one of them is your gateway, someone may be intercepting traffic (ARP spoofing). A Wi-Fi extender that clones client MACs can also cause this.",
		"flood":      "⚠️ ARP flood from one device",
		"floodTx":    "%d unsolicited ARP packets in %ds. Normal devices send a handful; tools that poison ARP caches send many.",
		"gateway":    "⚠️ Gateway %s answers from a new MAC",
		"gatewayTx":  "Expected if you replaced or reset the router. Otherwise check who now holds this address.",
		"was":        "Before",
		"now":        "Now",
		"dhcp":       "⚠️ Unexpected DHCP server on %s",
		"dhcpTx":     "Another device is handing out IP addresses. Clients that take its offer get its gateway and DNS. Often a bypass router (旁路由) or travel router with DHCP left on.",
		"server":     "Server",
		"trusted":    "Known server(s)",
		"offline":    "🔴 %s went offline",
		"online":     "🟢 %s is back online",
		"gone":       "Offline for %s",
		"ip":         "IP",
		"mac":        "MAC",
		"iface":      "Interface",
		"first":      "First seen",
		"random":     "randomized MAC",
		"unknown":    "Unknown device",
		"same":       "Probably “%s” with a new random MAC.",
		"more":       "…and %d more",
		"timeLayout": "2006-01-02 15:04",
	},
	"zh": {
		"new1":       "🐕 网络中出现新设备",
		"newN":       "🐕 网络中出现 %d 台新设备",
		"test":       "🐕 LanHound 测试消息——通知配置正常。",
		"conflict":   "🚨 IP 地址冲突：%s",
		"conflictGw": "🚨 网关 %s 疑似遭到 ARP 欺骗",
		"conflictTx": "两台设备同时声称拥有同一个 IP。如果其中一台是网关，可能有人在劫持流量（ARP 欺骗）；会克隆客户端 MAC 的 Wi-Fi 中继器也可能导致这种情况。",
		"flood":      "⚠️ 某设备在大量发送 ARP",
		"floodTx":    "%d 个未经请求的 ARP 包，用时 %d 秒。正常设备只会发几个，ARP 投毒工具会发大量。",
		"gateway":    "⚠️ 网关 %s 的 MAC 变了",
		"gatewayTx":  "如果刚换过或重置过路由器，属于正常；否则请查清现在是谁占着这个地址。",
		"was":        "之前",
		"now":        "现在",
		"dhcp":       "⚠️ %s 上出现了意外的 DHCP 服务器",
		"dhcpTx":     "有另一台设备在分配 IP。接受它分配的设备会用它指定的网关和 DNS。常见原因是旁路由或随身路由器没关 DHCP。",
		"server":     "服务器",
		"trusted":    "已知服务器",
		"offline":    "🔴 %s 离线了",
		"online":     "🟢 %s 恢复在线",
		"gone":       "离线时长 %s",
		"ip":         "IP",
		"mac":        "MAC",
		"iface":      "接口",
		"first":      "首次出现",
		"random":     "随机 MAC",
		"unknown":    "未知设备",
		"same":       "很可能是“%s”换了随机 MAC。",
		"more":       "……另有 %d 台",
		"timeLayout": "2006-01-02 15:04",
	},
}

func tr(lang, key string) string {
	if t, ok := texts[lang]; ok {
		return t[key]
	}
	return texts["en"][key]
}

// Render formats m as text. esc escapes device-supplied strings and
// bold/unbold wrap headings, so the same code produces Telegram HTML
// and plain text for webhooks.
func Render(m Message, lang string, esc func(string) string, bold, unbold string) string {
	r := renderer{lang: lang, esc: esc, bold: bold, unbold: unbold}
	switch m.Event {
	case EventTest:
		return tr(lang, "test")
	case EventNewDevice:
		r.newDevices(m)
	case EventARPConflict:
		key := "conflict"
		if m.Gateway {
			key = "conflictGw"
		}
		r.title(fmt.Sprintf(tr(lang, key), esc(m.IP)))
		for _, d := range m.Devices {
			r.deviceLine(d)
		}
		r.para(tr(lang, "conflictTx"))
	case EventARPFlood:
		r.title(tr(lang, "flood"))
		for _, d := range m.Devices {
			r.deviceLine(d)
		}
		r.para(fmt.Sprintf(tr(lang, "floodTx"), m.Count, m.Seconds))
	case EventGatewayChanged:
		r.title(fmt.Sprintf(tr(lang, "gateway"), esc(m.IP)))
		for i, d := range m.Devices {
			label := tr(lang, "was")
			if i > 0 {
				label = tr(lang, "now")
			}
			r.b.WriteString(label + ": ")
			r.deviceLine(d)
		}
		r.para(tr(lang, "gatewayTx"))
	case EventRogueDHCP:
		r.title(fmt.Sprintf(tr(lang, "dhcp"), esc(m.Interface)))
		r.b.WriteString(tr(lang, "server") + ": ")
		for _, d := range m.Devices {
			r.deviceLine(d)
		}
		if len(m.Trusted) > 0 {
			r.b.WriteString(tr(lang, "trusted") + ": " + esc(strings.Join(m.Trusted, ", ")) + "\n")
		}
		r.para(tr(lang, "dhcpTx"))
	case EventDeviceOffline, EventDeviceOnline:
		key := "offline"
		if m.Event == EventDeviceOnline {
			key = "online"
		}
		var d DeviceInfo
		if len(m.Devices) > 0 {
			d = m.Devices[0]
		}
		r.title(fmt.Sprintf(tr(lang, key), esc(r.name(d))))
		r.deviceLine(d)
		if m.Event == EventDeviceOnline && m.Seconds > 0 {
			r.b.WriteString(fmt.Sprintf(tr(lang, "gone"), humanDuration(time.Duration(m.Seconds)*time.Second, lang)) + "\n")
		}
	}
	return strings.TrimRight(r.b.String(), "\n")
}

type renderer struct {
	lang         string
	esc          func(string) string
	bold, unbold string
	b            strings.Builder
}

func (r *renderer) title(s string) { r.b.WriteString(r.bold + s + r.unbold + "\n") }
func (r *renderer) para(s string)  { r.b.WriteString("\n" + s + "\n") }

func (r *renderer) name(d DeviceInfo) string {
	return firstNonEmpty(d.Name, d.Hostname, d.Model, tr(r.lang, "unknown"))
}

// deviceLine is the compact one-line form: name · vendor · MAC (IP).
func (r *renderer) deviceLine(d DeviceInfo) {
	parts := []string{r.esc(r.name(d))}
	if d.Vendor != "" && !d.Randomized {
		parts = append(parts, r.esc(d.Vendor))
	}
	mac := r.esc(d.MAC)
	if d.IP != "" {
		mac += " (" + r.esc(d.IP) + ")"
	}
	parts = append(parts, mac)
	r.b.WriteString(strings.Join(parts, " · ") + "\n")
}

func (r *renderer) newDevices(m Message) {
	lang, esc, bold, unbold := r.lang, r.esc, r.bold, r.unbold
	b := &r.b
	if len(m.Devices) == 1 {
		r.title(tr(lang, "new1"))
	} else {
		r.title(fmt.Sprintf(tr(lang, "newN"), len(m.Devices)))
	}
	for i, d := range m.Devices {
		if i == maxListed {
			b.WriteString("\n" + fmt.Sprintf(tr(lang, "more"), len(m.Devices)-maxListed) + "\n")
			break
		}
		b.WriteString("\n")
		title := r.name(d)
		b.WriteString(bold + esc(title) + unbold)
		if d.Vendor != "" && !d.Randomized {
			b.WriteString(" · " + esc(d.Vendor))
		}
		if d.Model != "" && d.Model != title {
			b.WriteString(" · " + esc(d.Model))
		}
		b.WriteString("\n")
		if d.IP != "" {
			b.WriteString(tr(lang, "ip") + ": " + esc(d.IP) + "\n")
		}
		mac := esc(d.MAC)
		if d.Randomized {
			mac += " (" + tr(lang, "random") + ")"
		}
		b.WriteString(tr(lang, "mac") + ": " + mac + "\n")
		b.WriteString(tr(lang, "iface") + ": " + esc(d.Interface) + "\n")
		b.WriteString(tr(lang, "first") + ": " + d.FirstSeen.Format(tr(lang, "timeLayout")) + "\n")
		if d.SameAs != "" {
			b.WriteString("⚠️ " + fmt.Sprintf(tr(lang, "same"), esc(d.SameAs)) + "\n")
		}
	}
}

// humanDuration renders 3h12m / 3小时12分 style durations.
func humanDuration(d time.Duration, lang string) string {
	d = d.Round(time.Minute)
	h, m := int(d.Hours()), int(d.Minutes())%60
	day := h / 24
	h %= 24
	units := [3]string{"d", "h", "m"}
	if lang == "zh" {
		units = [3]string{"天", "小时", "分"}
	}
	var s string
	if day > 0 {
		s += fmt.Sprintf("%d%s", day, units[0])
	}
	if h > 0 {
		s += fmt.Sprintf("%d%s", h, units[1])
	}
	if m > 0 || s == "" {
		s += fmt.Sprintf("%d%s", m, units[2])
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
