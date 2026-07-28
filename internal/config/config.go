// Package config resolves where SYNSEC keeps its files and how it listens.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"synsec/internal/auth"
)

// DefaultPort is deliberately not 443 or 8443: SYNSEC should not collide with
// whatever else the household already runs, and should never need to be
// started with elevated privileges just to bind a port.
const DefaultPort = "8787"

// Environment variables that override the defaults, for people running SYNSEC
// in a container or from a service unit.
const (
	EnvDataDir        = "SYNSEC_DATA_DIR"
	EnvListen         = "SYNSEC_LISTEN"
	EnvSessionIdle    = "SYNSEC_SESSION_IDLE"
	EnvTLSCert        = "SYNSEC_TLS_CERT"
	EnvTLSKey         = "SYNSEC_TLS_KEY"
	EnvAuditRetain    = "SYNSEC_AUDIT_RETAIN"
	EnvTrustedProxies = "SYNSEC_TRUSTED_PROXIES"
	EnvWebAllow       = "SYNSEC_WEB_ALLOW"
	EnvRequire2FA     = "SYNSEC_REQUIRE_2FA"
)

// Config is the resolved runtime configuration.
type Config struct {
	// DataDir holds the database, the certificate and, on hosts with no
	// keystore, the key file.
	DataDir string

	// Listen is the address the HTTP server binds.
	//
	// It defaults to every interface rather than loopback: the entire point is
	// that a Home Assistant box on the same network can reach it. Serving only
	// localhost would mean nothing works until someone works out why.
	Listen string

	// TLSCert and TLSKey point at a certificate. Left empty, SYNSEC generates
	// and reuses a self-signed one in DataDir.
	//
	// There is no way to turn TLS off. A plain-HTTP mode would exist for the
	// reverse-proxy case and be used for everything else, and a secret server
	// that can be talked into answering in clear on a home network is a secret
	// server with a hole in it. A request that arrives without TLS is refused,
	// not downgraded.
	TLSCert string
	TLSKey  string

	// SessionIdle is how long a browser may sit untouched before the interface
	// signs it out. Activity pushes it back, so it only ever catches a tab
	// nobody is using.
	SessionIdle time.Duration

	// AuditRetain is how long audit entries are kept. Zero keeps them for
	// ever, which is the right default for a household: nobody wants to find
	// that the trace of an intrusion aged out. Set it on a server anyone can
	// reach, where failed sign-ins would otherwise fill the disk.
	AuditRetain time.Duration

	// TrustedProxies are the addresses whose X-Forwarded-For is believed.
	// Empty means the header is ignored, which is right for a server reached
	// directly and wrong behind a reverse proxy.
	TrustedProxies []string

	// WebAllow restricts the browser interface to a set of addresses. Empty
	// means anywhere, which is right on a home network and is the single
	// cheapest mitigation for a server anyone can reach.
	WebAllow []string

	// RequireSecondFactor makes a second factor compulsory for every account.
	//
	// Three states, which is why it is a pointer. Left unset, the interface
	// decides and the choice is stored in the database. Passed on the command
	// line, it wins either way - on, and no administrator can relax it from a
	// browser; off, and it is the way back for a server whose only root
	// account has locked itself out of its own policy.
	//
	// Off by default, because a household server where one person forgets
	// their phone and locks themselves out is a worse outcome than the risk it
	// removes. On a server anyone can reach it is the setting that matters
	// most: a password is the one credential that leaks somewhere else.
	//
	// It applies to the browser interface. Service tokens are unaffected -
	// there is no second factor a device could hold, and the token secret is
	// already 256 random bits.
	RequireSecondFactor *bool
}

// Default returns the configuration before any flag is applied.
func Default() Config {
	return Config{
		DataDir:     DefaultDataDir(),
		Listen:      envOr(EnvListen, ":"+DefaultPort),
		SessionIdle: envDuration(EnvSessionIdle, auth.SessionIdle),
		TLSCert:     os.Getenv(EnvTLSCert),
		TLSKey:      os.Getenv(EnvTLSKey),
		AuditRetain: envPlainDuration(EnvAuditRetain),

		TrustedProxies: envList(EnvTrustedProxies),
		WebAllow:       envList(EnvWebAllow),

		RequireSecondFactor: envSwitch(EnvRequire2FA),
	}
}

// envPlainDuration reads a duration with no clamping and no default. An
// unreadable or negative value means "no limit".
func envPlainDuration(key string) time.Duration {
	d, err := time.ParseDuration(os.Getenv(key))
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// envDuration reads a Go duration such as 30m or 8h.
//
// An unreadable value falls back to the default rather than failing to start:
// a typo in a service unit must not leave the household without its secrets.
func envDuration(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return auth.ClampSessionIdle(d)
}

// DefaultDataDir picks the conventional location for the platform.
//
// A system-wide directory is right because SYNSEC runs as a service, started
// before anyone logs in: a path under a user profile would not exist yet at
// the moment the service needs it.
func DefaultDataDir() string {
	if dir := os.Getenv(EnvDataDir); dir != "" {
		return dir
	}

	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("ProgramData"); base != "" {
			return filepath.Join(base, "SYNSEC")
		}
		return filepath.Join(os.Getenv("SystemDrive")+string(filepath.Separator), "SYNSEC")
	case "linux":
		return "/var/lib/synsec"
	default:
		return filepath.Join(os.Getenv("HOME"), ".local", "share", "synsec")
	}
}

// DatabasePath is where SQLite lives.
func (c Config) DatabasePath() string { return filepath.Join(c.DataDir, "synsec.db") }

// CertPath returns the certificate to use, generated if none was configured.
func (c Config) CertPath() string {
	if c.TLSCert != "" {
		return c.TLSCert
	}
	return filepath.Join(c.DataDir, "synsec.crt")
}

// KeyPath returns the private key matching CertPath.
func (c Config) KeyPath() string {
	if c.TLSKey != "" {
		return c.TLSKey
	}
	return filepath.Join(c.DataDir, "synsec.key")
}

// Prepare creates the data directory with restrictive permissions.
func (c Config) Prepare() error {
	if c.DataDir == "" {
		return fmt.Errorf("config: no data directory")
	}
	// 0700: on Linux the database and possibly the key file live here, and
	// nothing but the service account has any business reading them.
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return fmt.Errorf("config: creating %s: %w", c.DataDir, err)
	}
	return nil
}

// Validate reports configurations that cannot work.
func (c Config) Validate() error {
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("config: a certificate and its key must be given together")
	}
	return nil
}

// envList reads a comma-separated list.
func envList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// envSwitch reads a three-state switch. An unset or unreadable variable leaves
// the decision to the interface; anything a person would plausibly write for
// yes or no settles it here.
func envSwitch(key string) *bool {
	yes, no := true, false
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "oui", "yes", "on":
		return &yes
	case "0", "false", "non", "no", "off":
		return &no
	default:
		return nil
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
