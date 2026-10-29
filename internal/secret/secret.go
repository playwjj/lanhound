// Package secret masks stored secrets (bot tokens, passwords, API keys)
// for display, and recognizes a masked value coming back from the UI as
// "unchanged" so it never overwrites the real one.
package secret

import "strings"

// Mask is what the UI shows instead of a secret.
const Mask = "••••••"

// Hide masks a secret completely ("" stays "").
func Hide(v string) string {
	if v == "" {
		return ""
	}
	return Mask
}

// HideTail masks all but the last 4 characters, so a long token can be
// recognized without being revealed. Short values are hidden entirely.
func HideTail(v string) string {
	if len(v) <= 8 {
		return Hide(v)
	}
	return Mask + v[len(v)-4:]
}

// Keep returns stored when submitted is a masked value sent back
// unchanged, otherwise submitted as is (passwords may legitimately
// start or end with spaces; trim tokens yourself).
func Keep(submitted, stored string) string {
	if strings.HasPrefix(submitted, Mask) {
		return stored
	}
	return submitted
}
