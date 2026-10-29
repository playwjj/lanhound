// Package notify delivers alerts to Telegram and to a generic webhook.
// Messages carry what you need to tell friend from foe at a glance:
// name, vendor, IP, MAC and when the device first appeared.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"
)

// Events.
const (
	EventNewDevice = "new_device"
	EventTest      = "test"

	// Security alerts: detection only, LanHound never fights back.
	EventARPConflict    = "arp_conflict"    // one IP claimed by two MACs at once
	EventARPFlood       = "arp_flood"       // burst of unsolicited ARP from one MAC
	EventGatewayChanged = "gateway_changed" // the default gateway answers from a new MAC
	EventRogueDHCP      = "rogue_dhcp"      // an unexpected DHCP server answered

	// Devices marked critical.
	EventDeviceOffline = "device_offline"
	EventDeviceOnline  = "device_online"
)

// Category groups events for the per-category notification switches.
func Category(event string) string {
	switch event {
	case EventNewDevice:
		return "new"
	case EventDeviceOffline, EventDeviceOnline:
		return "critical"
	case EventTest:
		return "test"
	}
	return "security"
}

// Settings configures delivery. Empty fields disable a channel.
type Settings struct {
	Language       string `json:"language"` // "en" or "zh"
	NotifyNew      bool   `json:"notifyNew"`
	NotifySecurity bool   `json:"notifySecurity"`
	NotifyCritical bool   `json:"notifyCritical"`
	TelegramToken  string `json:"telegramToken"`
	TelegramChatID string `json:"telegramChatId"`
	TelegramAPI    string `json:"telegramApi"` // Bot API base URL, for self-hosted proxies
	WebhookURL     string `json:"webhookUrl"`
}

// DefaultTelegramAPI is the official Bot API endpoint.
const DefaultTelegramAPI = "https://api.telegram.org"

// Telegram reports whether the Telegram channel is configured.
func (s Settings) Telegram() bool { return s.TelegramToken != "" && s.TelegramChatID != "" }

// Wants reports whether alerts of this event's category are switched on.
func (s Settings) Wants(event string) bool {
	switch Category(event) {
	case "new":
		return s.NotifyNew
	case "critical":
		return s.NotifyCritical
	case "security":
		return s.NotifySecurity
	}
	return true
}

// Configured reports whether any channel is set up.
func (s Settings) Configured() bool { return s.Telegram() || s.WebhookURL != "" }

// DeviceInfo describes one device in an alert.
type DeviceInfo struct {
	ID         int64     `json:"id,omitempty"` // 0 for a MAC LanHound has no device record for
	Name       string    `json:"name,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	Model      string    `json:"model,omitempty"`
	IP         string    `json:"ip,omitempty"`
	MAC        string    `json:"mac"`
	Interface  string    `json:"interface"`
	FirstSeen  time.Time `json:"firstSeen"`
	Randomized bool      `json:"randomized"`
	SameNameAs string    `json:"sameNameAs,omitempty"` // an existing device with the same hostname
}

// Message is one alert. Which fields are set depends on Event:
//
//	new_device       Devices (one or more new devices)
//	arp_conflict     IP, Gateway, Devices (the claimants: established first)
//	arp_flood        Devices (the sender), Count, Seconds
//	gateway_changed  IP, Devices (old MAC, new MAC)
//	rogue_dhcp       IP (server identifier), Devices (the server), Trusted (known servers), Key
//	device_offline   Devices (the device)
//	device_online    Devices (the device), Seconds (how long it was gone)
type Message struct {
	Event     string       `json:"event"`
	Interface string       `json:"interface,omitempty"`
	IP        string       `json:"ip,omitempty"`
	Gateway   bool         `json:"gateway,omitempty"`
	Count     int          `json:"count,omitempty"`
	Seconds   int64        `json:"seconds,omitempty"`
	Trusted   []string     `json:"trusted,omitempty"`
	Key       string       `json:"key,omitempty"` // rogue_dhcp: what to pass to "trust this server"
	Devices   []DeviceInfo `json:"devices"`
}

var client = &http.Client{Timeout: 15 * time.Second}

// Send delivers m to every configured channel. Errors from individual
// channels are joined; one failing channel does not stop the others.
func Send(ctx context.Context, s Settings, m Message) error {
	if !s.Configured() {
		return errors.New("no notification channel configured")
	}
	var errs []error
	if s.Telegram() {
		if err := sendTelegram(ctx, s, m); err != nil {
			errs = append(errs, fmt.Errorf("telegram: %w", err))
		}
	}
	if s.WebhookURL != "" {
		if err := sendWebhook(ctx, s, m); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	return errors.Join(errs...)
}

func sendTelegram(ctx context.Context, s Settings, m Message) error {
	base := strings.TrimRight(s.TelegramAPI, "/")
	if base == "" {
		base = DefaultTelegramAPI
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id":                  s.TelegramChatID,
		"text":                     Render(m, s.Language, html.EscapeString, "<b>", "</b>"),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	})
	return post(ctx, base+"/bot"+s.TelegramToken+"/sendMessage", body, s.TelegramToken)
}

// webhookPayload is what the webhook receives. text/content duplicate
// the human-readable message so Slack- and Discord-style endpoints
// render something useful without an adapter.
type webhookPayload struct {
	Message
	Text    string `json:"text"`
	Content string `json:"content"`
}

func sendWebhook(ctx context.Context, s Settings, m Message) error {
	text := Render(m, s.Language, func(s string) string { return s }, "", "")
	body, _ := json.Marshal(webhookPayload{Message: m, Text: text, Content: text})
	return post(ctx, s.WebhookURL, body, "")
}

// post sends JSON and turns non-2xx answers into errors. secret is
// scrubbed from error messages (the Telegram token is part of the URL).
func post(ctx context.Context, url string, body []byte, secret string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return scrub(err, secret)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LanHound")
	resp, err := client.Do(req)
	if err != nil {
		return scrub(err, secret)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return scrub(fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg))), secret)
	}
	return nil
}

func scrub(err error, secret string) error {
	if secret == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "***"))
}
