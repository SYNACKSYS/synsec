package main

import (
	"flag"
	"strings"
	"testing"
	"time"

	"synsec/internal/config"
)

// A service installed with options has to come back with them after a reboot.
// The two declarations drifted once already; these hold them together.

func TestServiceKeepsTheOptionsItWasGiven(t *testing.T) {
	cfg := config.Default()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	apply := serveOptions(fs, &cfg)

	if err := fs.Parse([]string{
		"-data", "/srv/synsec",
		"-listen", ":9000",
		"-web-allow", "192.168.1.0/24,203.0.113.7",
		"-trusted-proxies", "10.0.0.0/8",
		"-audit-retain", "8760h",
		"-require-2fa",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	apply()

	line := strings.Join(serveArgs(cfg), " ")
	for _, want := range []string{
		"serve", "-data /srv/synsec", "-listen :9000",
		"-web-allow 192.168.1.0/24,203.0.113.7",
		"-trusted-proxies 10.0.0.0/8",
		"-audit-retain 8760h0m0s",
		"-require-2fa=true",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the service would run %q, which is missing %q", line, want)
		}
	}
}

// A setting nobody chose must not appear as though somebody had.
func TestUntouchedOptionsAreNotWrittenOut(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir, cfg.Listen = "/srv/synsec", ":8787"

	line := strings.Join(serveArgs(cfg), " ")
	for _, absent := range []string{"-require-2fa", "-web-allow", "-audit-retain", "-session-idle"} {
		if strings.Contains(line, absent) {
			t.Errorf("%q appears in %q although nothing set it", absent, line)
		}
	}
}

// Off has to survive the round trip as well as on: it is the way back for a
// server whose only account has locked itself out of its own policy.
func TestThePolicyCanBePinnedOff(t *testing.T) {
	cfg := config.Default()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	apply := serveOptions(fs, &cfg)

	if err := fs.Parse([]string{"-require-2fa=false"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	apply()

	if cfg.RequireSecondFactor == nil {
		t.Fatal("an explicit -require-2fa=false left the decision to the interface")
	}
	if *cfg.RequireSecondFactor {
		t.Fatal("-require-2fa=false turned the policy on")
	}
	if line := strings.Join(serveArgs(cfg), " "); !strings.Contains(line, "-require-2fa=false") {
		t.Fatalf("the service would run %q, losing the pin", line)
	}
}

// The session timeout is clamped, so writing it out and reading it back must
// land on the same value rather than drift each time the service is reinstalled.
func TestTheSessionTimeoutSurvivesTheRoundTrip(t *testing.T) {
	cfg := config.Default()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	apply := serveOptions(fs, &cfg)

	if err := fs.Parse([]string{"-session-idle", "45m"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	apply()

	if cfg.SessionIdle != 45*time.Minute {
		t.Fatalf("the timeout became %s", cfg.SessionIdle)
	}
	if line := strings.Join(serveArgs(cfg), " "); !strings.Contains(line, "-session-idle 45m0s") {
		t.Fatalf("the service would run %q", line)
	}
}
