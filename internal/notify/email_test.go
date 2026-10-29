package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP speaks just enough SMTP for net/smtp, without TLS.
type fakeSMTP struct {
	mu       sync.Mutex
	auth     string
	from     string
	rcpt     []string
	data     string
	startTLS bool // advertise STARTTLS
}

func (f *fakeSMTP) serve(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	return l.Addr().String()
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		up := strings.ToUpper(cmd)
		f.mu.Lock()
		switch {
		case strings.HasPrefix(up, "EHLO"):
			if f.startTLS {
				say("250-fake\r\n250-STARTTLS")
			}
			say("250-fake\r\n250 AUTH PLAIN")
		case strings.HasPrefix(up, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(cmd[len("AUTH PLAIN"):]))
			f.auth = strings.ReplaceAll(string(raw), "\x00", "|")
			say("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.from = cmd[len("MAIL FROM:"):]
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			f.rcpt = append(f.rcpt, cmd[len("RCPT TO:"):])
			say("250 ok")
		case up == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.data = b.String()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			f.mu.Unlock()
			return
		default:
			say("250 ok")
		}
		f.mu.Unlock()
	}
}

func TestSendEmail(t *testing.T) {
	f := &fakeSMTP{}
	host, port, _ := net.SplitHostPort(f.serve(t))
	s := Settings{Language: "zh", SMTPHost: host, SMTPPort: port, SMTPSecurity: SMTPNone, SMTPUser: "me", SMTPPassword: "test-only",
		SMTPFrom: "LanHound <lanhound@example.com>", SMTPTo: "a@example.com, b@example.com"}
	if !s.Email() || !s.Configured() {
		t.Fatal("email should count as configured")
	}
	m := Message{Event: EventNewDevice, Devices: []DeviceInfo{{MAC: "da:00:00:00:00:51", Hostname: ".hidden", IP: "192.168.2.9", FirstSeen: time.Now()}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Send(ctx, s, m); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "|me|test-only" || f.from != "<lanhound@example.com>" || len(f.rcpt) != 2 {
		t.Fatalf("auth %q from %q rcpt %v", f.auth, f.from, f.rcpt)
	}
	for _, want := range []string{"Subject: =?utf-8?q?", "To: a@example.com, b@example.com", "charset=utf-8", "IP: 192.168.2.9", "\r\n-- \r\nLanHound"} {
		if !strings.Contains(f.data, want) {
			t.Errorf("message lacks %q:\n%s", want, f.data)
		}
	}
	// A body line starting with "." must be escaped, or it could end
	// the message early.
	if !strings.Contains(f.data, "\r\n...hidden") && !strings.Contains(f.data, "..hidden") {
		t.Errorf("dot-stuffing missing:\n%s", f.data)
	}
}

func TestSendEmailRequiresSTARTTLS(t *testing.T) {
	f := &fakeSMTP{} // no STARTTLS offered
	host, port, _ := net.SplitHostPort(f.serve(t))
	s := Settings{SMTPHost: host, SMTPPort: port, SMTPFrom: "a@example.com", SMTPTo: "b@example.com"} // default: starttls
	err := Send(context.Background(), s, Message{Event: EventTest})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want a STARTTLS error, got %v", err)
	}
}

func TestParseSMTPURL(t *testing.T) {
	s, err := ParseSMTPURL("smtps://me:p%40ss@smtp.example.com?from=lh@example.com&to=a@example.com,b@example.com")
	if err != nil || s.SMTPSecurity != SMTPTLS || s.SMTPPort != "465" || s.SMTPPassword != "p@ss" || len(recipients(s.SMTPTo)) != 2 {
		t.Fatalf("%+v %v", s, err)
	}
	s, _ = ParseSMTPURL("smtp://smtp.qq.com:587?from=x@qq.com&to=y@qq.com")
	if s.SMTPSecurity != SMTPStartTLS || s.SMTPHost != "smtp.qq.com" {
		t.Fatalf("%+v", s)
	}
	for _, bad := range []string{"http://x", "smtp://host", "smtp://host?from=a@b.c"} {
		if _, err := ParseSMTPURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
