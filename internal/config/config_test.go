package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAreUsable(t *testing.T) {
	t.Setenv(EnvDataDir, "")
	t.Setenv(EnvListen, "")

	cfg := Default()
	if cfg.DataDir == "" {
		t.Fatal("the default configuration has no data directory")
	}
	if !strings.HasSuffix(cfg.Listen, ":"+DefaultPort) {
		t.Fatalf("the default listen address is %q", cfg.Listen)
	}

	// Listening only on loopback would mean nothing on the network can reach
	// the server, which is the entire point of it.
	if strings.HasPrefix(cfg.Listen, "127.0.0.1") || strings.HasPrefix(cfg.Listen, "localhost") {
		t.Fatalf("the default binds loopback only: %q", cfg.Listen)
	}
}

func TestEnvironmentOverrides(t *testing.T) {
	t.Setenv(EnvDataDir, filepath.Join("tmp", "synsec-data"))
	t.Setenv(EnvListen, "127.0.0.1:9999")

	cfg := Default()
	if cfg.DataDir != filepath.Join("tmp", "synsec-data") {
		t.Fatalf("the data directory is %q", cfg.DataDir)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Fatalf("the listen address is %q", cfg.Listen)
	}
}

func TestDerivedPaths(t *testing.T) {
	cfg := Config{DataDir: filepath.Join("var", "synsec")}

	if got, want := cfg.DatabasePath(), filepath.Join("var", "synsec", "synsec.db"); got != want {
		t.Errorf("DatabasePath is %q, want %q", got, want)
	}
	if got, want := cfg.CertPath(), filepath.Join("var", "synsec", "synsec.crt"); got != want {
		t.Errorf("CertPath is %q, want %q", got, want)
	}

	// An explicit certificate wins over the derived location.
	explicit := Config{DataDir: "var", TLSCert: "mon.crt", TLSKey: "ma.key"}
	if explicit.CertPath() != "mon.crt" || explicit.KeyPath() != "ma.key" {
		t.Error("an explicitly configured certificate was ignored")
	}
}

func TestValidateRejectsHalfConfiguredTLS(t *testing.T) {
	// A certificate without its key would fail at startup with an obscure
	// message; catching it here says what is actually wrong.
	if err := (Config{TLSCert: "mon.crt"}).Validate(); err == nil {
		t.Error("a certificate without a key was accepted")
	}
	if err := (Config{TLSKey: "ma.key"}).Validate(); err == nil {
		t.Error("a key without a certificate was accepted")
	}
	if err := (Config{TLSCert: "mon.crt", TLSKey: "ma.key"}).Validate(); err != nil {
		t.Errorf("a complete certificate pair was rejected: %v", err)
	}
	// No certificate at all is valid: SYNSEC generates its own.
	if err := (Config{}).Validate(); err != nil {
		t.Errorf("the default configuration was rejected: %v", err)
	}
}

func TestPrepareCreatesTheDirectory(t *testing.T) {
	cfg := Config{DataDir: filepath.Join(t.TempDir(), "nested", "synsec")}
	if err := cfg.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := cfg.Prepare(); err != nil {
		t.Fatalf("Prepare is not idempotent: %v", err)
	}

	if err := (Config{}).Prepare(); err == nil {
		t.Error("Prepare accepted an empty data directory")
	}
}
