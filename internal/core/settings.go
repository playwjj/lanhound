package core

import (
	"strings"
	"sync"

	"github.com/playwjj/lanhound/internal/notify"
	"github.com/playwjj/lanhound/internal/secret"
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

// mask is kept as a local name for the tests.
const mask = secret.Mask

// NewSettings loads stored settings and applies env overrides.
func NewSettings(st *store.Store, env notify.Settings) (*Settings, error) {
	// Defaults for switches missing from older stored settings.
	s := &Settings{store: st, env: env, cur: notify.Settings{NotifyNew: true, NotifySecurity: true, NotifyCritical: true}}
	if _, err := st.GetJSON(settingsKey, &s.cur); err != nil {
		return nil, err
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
	if e.SMTPSecurity == "" {
		e.SMTPSecurity = notify.SMTPStartTLS
	}
	if e.EmailVia == "" {
		e.EmailVia = notify.ViaSMTP
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
		{"emailVia", &s.env.EmailVia, func(n *notify.Settings) *string { return &n.EmailVia }},
		{"resendKey", &s.env.ResendKey, func(n *notify.Settings) *string { return &n.ResendKey }},
		{"smtpHost", &s.env.SMTPHost, func(n *notify.Settings) *string { return &n.SMTPHost }},
		{"smtpPort", &s.env.SMTPPort, func(n *notify.Settings) *string { return &n.SMTPPort }},
		{"smtpSecurity", &s.env.SMTPSecurity, func(n *notify.Settings) *string { return &n.SMTPSecurity }},
		{"smtpUser", &s.env.SMTPUser, func(n *notify.Settings) *string { return &n.SMTPUser }},
		{"smtpPassword", &s.env.SMTPPassword, func(n *notify.Settings) *string { return &n.SMTPPassword }},
		{"smtpFrom", &s.env.SMTPFrom, func(n *notify.Settings) *string { return &n.SMTPFrom }},
		{"smtpTo", &s.env.SMTPTo, func(n *notify.Settings) *string { return &n.SMTPTo }},
	}
}

// Public returns the settings for display.
func (s *Settings) Public() PublicSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := PublicSettings{Settings: s.effective(), Locked: []string{}}
	p.TelegramToken = secret.HideTail(p.TelegramToken) // the tail tells which bot it is
	p.SMTPPassword = secret.Hide(p.SMTPPassword)
	p.ResendKey = secret.Hide(p.ResendKey)
	for _, f := range s.fields() {
		if *f.env != "" {
			p.Locked = append(p.Locked, f.name)
		}
	}
	return p
}

// Put stores new settings. A masked token (as returned by Public)
// means "unchanged".
func (s *Settings) Put(n notify.Settings) (notify.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keepSecrets(&n)
	if n.EmailVia != notify.ViaResend {
		n.EmailVia = notify.ViaSMTP
	}
	n.SMTPHost = strings.TrimSpace(n.SMTPHost)
	n.SMTPPort = strings.TrimSpace(n.SMTPPort)
	n.SMTPFrom = strings.TrimSpace(n.SMTPFrom)
	n.SMTPTo = strings.TrimSpace(n.SMTPTo)
	switch n.SMTPSecurity {
	case notify.SMTPTLS, notify.SMTPNone:
	default:
		n.SMTPSecurity = notify.SMTPStartTLS
	}
	n.TelegramChatID = strings.TrimSpace(n.TelegramChatID)
	n.TelegramAPI = strings.TrimSpace(n.TelegramAPI)
	n.WebhookURL = strings.TrimSpace(n.WebhookURL)
	if n.Language != "zh" {
		n.Language = "en"
	}
	if err := s.store.PutJSON(settingsKey, n); err != nil {
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
	s.keepSecrets(&n)
	saved := s.cur
	s.cur = n
	e := s.effective()
	s.cur = saved
	return e
}

// keepSecrets puts the stored secrets back where the UI sent masks.
// Caller holds s.mu.
func (s *Settings) keepSecrets(n *notify.Settings) {
	n.TelegramToken = strings.TrimSpace(secret.Keep(n.TelegramToken, s.cur.TelegramToken))
	n.SMTPPassword = secret.Keep(n.SMTPPassword, s.cur.SMTPPassword)
	n.ResendKey = strings.TrimSpace(secret.Keep(n.ResendKey, s.cur.ResendKey))
}
