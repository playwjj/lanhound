package notify

import (
	"fmt"
	"strings"
)

// maxListed caps how many devices one message spells out.
const maxListed = 10

var texts = map[string]map[string]string{
	"en": {
		"new1":       "🐕 New device on your network",
		"newN":       "🐕 %d new devices on your network",
		"test":       "🐕 LanHound test message — notifications work.",
		"ip":         "IP",
		"mac":        "MAC",
		"iface":      "Interface",
		"first":      "First seen",
		"random":     "randomized MAC",
		"unknown":    "Unknown device",
		"same":       "Same hostname as “%s” — probably a new random MAC of it.",
		"more":       "…and %d more",
		"timeLayout": "2006-01-02 15:04",
	},
	"zh": {
		"new1":       "🐕 网络中出现新设备",
		"newN":       "🐕 网络中出现 %d 台新设备",
		"test":       "🐕 LanHound 测试消息——通知配置正常。",
		"ip":         "IP",
		"mac":        "MAC",
		"iface":      "接口",
		"first":      "首次出现",
		"random":     "随机 MAC",
		"unknown":    "未知设备",
		"same":       "与“%s”主机名相同——很可能是它换了随机 MAC。",
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
	var b strings.Builder
	if m.Event == EventTest {
		return tr(lang, "test")
	}
	if len(m.Devices) == 1 {
		b.WriteString(bold + tr(lang, "new1") + unbold + "\n")
	} else {
		b.WriteString(bold + fmt.Sprintf(tr(lang, "newN"), len(m.Devices)) + unbold + "\n")
	}
	for i, d := range m.Devices {
		if i == maxListed {
			b.WriteString("\n" + fmt.Sprintf(tr(lang, "more"), len(m.Devices)-maxListed) + "\n")
			break
		}
		b.WriteString("\n")
		title := firstNonEmpty(d.Name, d.Hostname, d.Model, tr(lang, "unknown"))
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
		if d.SameNameAs != "" {
			b.WriteString("⚠️ " + fmt.Sprintf(tr(lang, "same"), esc(d.SameNameAs)) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
