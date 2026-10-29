package core

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/store"
)

const settingsKey = "notify"

// Settings holds the notification settings. Values come from the web
// UI (stored in the database); environment variables, when set, win
// and are shown as locked in the UI.
type Settings struct {
	store *store.Store
	env   notify.Settings

	mu  sync.Mutex
	cur notify.Settings
}

// PublicSettings is what the API exposes: secrets masked, locked
// fields flagged.
type PublicSettings struct {
	notify.Settings
	Locked []string `json:"locked"`
}

const mask = "••••••"

// NewSettings loads stored settings and applies env overrides.
func NewSettings(st *store.Store, env notify.Settings) (*Settings, error) {
	// Defaults for switches missing from older stored settings.
	s := &Settings{store: st, env: env, cur: notify.Settings{NotifyNew: true, NotifySecurity: true, NotifyCritical: true}}
	raw, err := st.Setting(settingsKey)
	if err != nil {
		return nil, err
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &s.cur); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Get returns the effective settings.
func (s *Settings) Get() notify.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effective()
}

func (s *Settings) effective() notify.Settings {
	e := s.cur
	for _, f := range s.fields() {
		if v := *f.env; v != "" {
			*f.dst(&e) = v
		}
	}
	if e.Language == "" {
		e.Language = "en"
	}
	return e
}

type field struct {
	name string
	env  *string
	dst  func(*notify.Settings) *string
}

func (s *Settings) fields() []field {
	return []field{
		{"language", &s.env.Language, func(n *notify.Settings) *string { return &n.Language }},
		{"telegramToken", &s.env.TelegramToken, func(n *notify.Settings) *string { return &n.TelegramToken }},
		{"telegramChatId", &s.env.TelegramChatID, func(n *notify.Settings) *string { return &n.TelegramChatID }},
		{"telegramApi", &s.env.TelegramAPI, func(n *notify.Settings) *string { return &n.TelegramAPI }},
		{"webhookUrl", &s.env.WebhookURL, func(n *notify.Settings) *string { return &n.WebhookURL }},
	}
}

// Public returns the settings for display.
func (s *Settings) Public() PublicSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := PublicSettings{Settings: s.effective(), Locked: []string{}}
	if p.TelegramToken != "" {
		p.TelegramToken = maskSecret(p.TelegramToken)
	}
	for _, f := range s.fields() {
		if *f.env != "" {
			p.Locked = append(p.Locked, f.name)
		}
	}
	return p
}

// maskSecret keeps the last 4 characters so the user can recognize
// which token is configured.
func maskSecret(v string) string {
	if len(v) <= 8 {
		return mask
	}
	return mask + v[len(v)-4:]
}

// Put stores new settings. A masked token (as returned by Public)
// means "unchanged".
func (s *Settings) Put(n notify.Settings) (notify.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.HasPrefix(n.TelegramToken, mask) {
		n.TelegramToken = s.cur.TelegramToken
	}
	n.TelegramToken = strings.TrimSpace(n.TelegramToken)
	n.TelegramChatID = strings.TrimSpace(n.TelegramChatID)
	n.TelegramAPI = strings.TrimSpace(n.TelegramAPI)
	n.WebhookURL = strings.TrimSpace(n.WebhookURL)
	if n.Language != "zh" {
		n.Language = "en"
	}
	b, _ := json.Marshal(n)
	if err := s.store.SetSetting(settingsKey, string(b)); err != nil {
		return notify.Settings{}, err
	}
	s.cur = n
	return s.effective(), nil
}

// Resolve applies a candidate (possibly masked) settings value on top of
// the stored ones without saving it — used by "send test message".
func (s *Settings) Resolve(n notify.Settings) notify.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.HasPrefix(n.TelegramToken, mask) {
		n.TelegramToken = s.cur.TelegramToken
	}
	saved := s.cur
	s.cur = n
	e := s.effective()
	s.cur = saved
	return e
}
