package alert

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"synsec/internal/vault"
)

// Where the configuration lives.
//
// Two of these four are credentials and go through the root key. A webhook
// address very often is the whole credential - a Discord or an ntfy URL is a
// bearer token with a hostname in front of it - and the signing key is one by
// definition. Storing them in the clear inside a database whose reason to
// exist is that its contents are not would be a poor advertisement.
//
// The consequence is stated rather than hidden: a sealed server cannot read
// them, so it cannot alert. It cannot serve a secret either, so there is
// nothing it would have to say.
const (
	SettingEnabled = "alert_enabled"
	SettingLevel   = "alert_level"
	SettingURL     = "alert_webhook_url"    // sealed
	SettingSecret  = "alert_webhook_secret" // sealed
)

// LoadConfig reads the current settings. server names this installation in the
// messages it sends.
func LoadConfig(ctx context.Context, m *vault.Manager, server string) (Config, error) {
	enabled, err := m.DB().ServerSetting(ctx, SettingEnabled, "")
	if err != nil {
		return Config{}, err
	}
	level, err := m.DB().ServerSetting(ctx, SettingLevel, SeverityWarning.String())
	if err != nil {
		return Config{}, err
	}
	sev, ok := ParseSeverity(level)
	if !ok {
		sev = SeverityWarning
	}

	cfg := Config{Enabled: enabled == "1", Level: sev}

	// Reading the address costs a decryption, so it is skipped entirely when
	// nothing is switched on - which is also what keeps a sealed server from
	// logging an error every two seconds about a setting nobody asked for.
	if !cfg.Enabled {
		return cfg, nil
	}

	url, err := m.SealedSetting(ctx, SettingURL, "")
	if err != nil {
		return cfg, err
	}
	secret, err := m.SealedSetting(ctx, SettingSecret, "")
	if err != nil {
		return cfg, err
	}
	cfg.Webhook = Webhook{URL: url, Secret: secret, Server: server}
	return cfg, nil
}

// SaveWebhook stores the destination, generating a signing key the first time.
//
// The key is made here rather than typed: it exists so the receiver can tell a
// real message from an invented one, and a key somebody chose by hand is one
// they will choose badly.
func SaveWebhook(ctx context.Context, m *vault.Manager, rawURL string) (secret string, err error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		if err := m.SetSealedSetting(ctx, SettingURL, ""); err != nil {
			return "", err
		}
		return "", m.SetSealedSetting(ctx, SettingSecret, "")
	}
	if err := ValidateURL(rawURL); err != nil {
		return "", err
	}
	if err := m.SetSealedSetting(ctx, SettingURL, rawURL); err != nil {
		return "", err
	}

	// An existing key is kept: changing the address of a receiver should not
	// silently break the signature check it was set up with.
	secret, err = m.SealedSetting(ctx, SettingSecret, "")
	if err != nil {
		return "", err
	}
	if secret != "" {
		return secret, nil
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("alert: generating the signing key: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	return secret, m.SetSealedSetting(ctx, SettingSecret, secret)
}
