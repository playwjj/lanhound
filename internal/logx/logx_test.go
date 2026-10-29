package logx

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestSetupLevelsFormatAndRing(t *testing.T) {
	var buf bytes.Buffer
	if err := Setup("warn", "json", &buf); err != nil {
		t.Fatal(err)
	}
	L("router").Info("hidden")
	L("router").Warn("router unreachable", "router", "OpenWrt", "err", "timeout")
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, `"component":"router"`) || !strings.Contains(out, `"level":"WARN"`) {
		t.Fatalf("output %s", out)
	}
	got := Recent()
	if len(got) == 0 || got[0].Msg != "router unreachable" || got[0].Attrs["component"] != "router" || got[0].Attrs["router"] != "OpenWrt" {
		t.Fatalf("ring %+v", got)
	}
	if err := Setup("loud", "text", &buf); err == nil {
		t.Fatal("bad level accepted")
	}
	if err := Setup("info", "xml", &buf); err == nil {
		t.Fatal("bad format accepted")
	}
}

func TestRingKeepsWarningsEvenWhenFilteredOut(t *testing.T) {
	var buf bytes.Buffer
	_ = Setup("error", "text", &buf)
	L("hass").Warn("mqtt down")
	if strings.Contains(buf.String(), "mqtt down") {
		t.Fatal("warn printed at error level")
	}
	if Recent()[0].Msg != "mqtt down" {
		t.Fatal("diagnostics must keep warnings regardless of the print level")
	}
}

func TestRingIsBounded(t *testing.T) {
	var buf bytes.Buffer
	_ = Setup("error", "text", &buf)
	for i := 0; i < ringSize+50; i++ {
		slog.Warn("w")
	}
	if n := len(Recent()); n != ringSize {
		t.Fatalf("ring holds %d", n)
	}
}

func TestFailuresCollapseRetries(t *testing.T) {
	var buf bytes.Buffer
	_ = Setup("info", "text", &buf)
	var f Failures
	l := L("router")
	for i := 0; i < 10; i++ {
		f.Fail(l, "r1", "router unreachable", errors.New("dial tcp: i/o timeout"))
	}
	f.Fail(l, "r1", "router unreachable", errors.New("HTTP 401"))
	f.OK(l, "r1", "router reachable again")
	f.OK(l, "r1", "router reachable again") // not failing: silent
	out := buf.String()
	if n := strings.Count(out, "router unreachable"); n != 2 {
		t.Fatalf("want 2 warnings (start + changed error), got %d:\n%s", n, out)
	}
	if strings.Count(out, "router reachable again") != 1 || !strings.Contains(out, "failures=11") {
		t.Fatalf("recovery line missing or repeated:\n%s", out)
	}
}
