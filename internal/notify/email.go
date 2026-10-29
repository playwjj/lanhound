package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SMTP security modes.
const (
	SMTPStartTLS = "starttls" // port 587: plain connection upgraded to TLS
	SMTPTLS      = "tls"      // port 465: TLS from the first byte
	SMTPNone     = "none"     // no encryption (local relays only)
)

// Email reports whether the email channel is configured.
func (s Settings) Email() bool {
	return s.SMTPHost != "" && s.SMTPFrom != "" && len(recipients(s.SMTPTo)) > 0
}

func recipients(list string) []string {
	var out []string
	for _, a := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if addr, err := mail.ParseAddress(a); err == nil {
			out = append(out, addr.Address)
		}
	}
	return out
}

// ParseSMTPURL reads LANHOUND_SMTP_URL:
//
//	smtp://user:pass@host:587?from=lanhound@example.com&to=me@example.com,you@example.com
//
// smtp:// means STARTTLS (587 by default), smtps:// implicit TLS (465)
// and smtp+plain:// no encryption (25).
func ParseSMTPURL(raw string) (Settings, error) {
	var s Settings
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return s, fmt.Errorf("bad SMTP URL %q", raw)
	}
	switch u.Scheme {
	case "smtp":
		s.SMTPSecurity, s.SMTPPort = SMTPStartTLS, "587"
	case "smtps":
		s.SMTPSecurity, s.SMTPPort = SMTPTLS, "465"
	case "smtp+plain":
		s.SMTPSecurity, s.SMTPPort = SMTPNone, "25"
	default:
		return s, fmt.Errorf("unsupported SMTP scheme %q (use smtp://, smtps:// or smtp+plain://)", u.Scheme)
	}
	s.SMTPHost = u.Hostname()
	if p := u.Port(); p != "" {
		s.SMTPPort = p
	}
	if u.User != nil {
		s.SMTPUser = u.User.Username()
		s.SMTPPassword, _ = u.User.Password()
	}
	s.SMTPFrom = u.Query().Get("from")
	s.SMTPTo = u.Query().Get("to")
	if s.SMTPFrom == "" || len(recipients(s.SMTPTo)) == 0 {
		return s, errors.New("SMTP URL needs ?from=…&to=…")
	}
	return s, nil
}

// emailMessage builds a plain-text UTF-8 message.
func emailMessage(s Settings, m Message, now time.Time) []byte {
	lang := s.Language
	subject := Describe(m, lang, func(x string) string { return x }).Title
	body := Render(m, lang, func(x string) string { return x }, "", "")
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", s.SMTPFrom)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(recipients(s.SMTPTo), ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	// SMTP needs CRLF line endings, and a lone "." line ends the message.
	for _, line := range strings.Split(body+"\n\n-- \nLanHound", "\n") {
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		b.WriteString(line + "\r\n")
	}
	return b.Bytes()
}

func sendEmail(ctx context.Context, s Settings, m Message) error {
	port := s.SMTPPort
	if port == "" {
		port = map[string]string{SMTPTLS: "465", SMTPNone: "25"}[s.SMTPSecurity]
		if port == "" {
			port = "587"
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("bad SMTP port %q", port)
	}
	addr := net.JoinHostPort(s.SMTPHost, port)
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	d := net.Dialer{Deadline: deadline}
	tlsCfg := &tls.Config{ServerName: s.SMTPHost}

	var conn net.Conn
	var err error
	if s.SMTPSecurity == SMTPTLS {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, s.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if s.SMTPSecurity != SMTPTLS && s.SMTPSecurity != SMTPNone {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS (choose SSL/TLS or none)")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if s.SMTPUser != "" {
		// smtp.PlainAuth itself refuses to send the password over an
		// unencrypted connection to anything but localhost.
		if err := c.Auth(smtp.PlainAuth("", s.SMTPUser, s.SMTPPassword, s.SMTPHost)); err != nil {
			return fmt.Errorf("login: %w", err)
		}
	}
	from, err := mail.ParseAddress(s.SMTPFrom)
	if err != nil {
		return fmt.Errorf("bad sender %q", s.SMTPFrom)
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	for _, rcpt := range recipients(s.SMTPTo) {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("recipient %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(emailMessage(s, m, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
