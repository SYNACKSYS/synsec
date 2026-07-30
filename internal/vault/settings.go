package vault

import (
	"context"
	"encoding/base64"
	"fmt"

	"synsec/internal/crypto"
)

// Server settings that are themselves credentials.
//
// Most settings are plain: a timeout, a policy flag, a display size. A few are
// not. The address of a webhook is often the whole credential - a Discord or
// ntfy URL is a bearer token with a hostname in front - and the key used to
// sign the messages is one by definition.
//
// Those go through the root key, like a secret, rather than sitting in the
// clear in a database whose entire purpose is that its contents do not. The
// cost is that they can only be read while the server is unsealed, which is
// also when it can do anything at all.

// sealedSettingDomain separates these from any other use of the root key, and
// binds each value to its own name: a blob moved from one setting to another
// fails to open rather than being read as something it is not.
const sealedSettingDomain = "setting"

// SealedSetting reads a setting that was stored encrypted.
//
// A setting that was never written returns the fallback, like the plain ones.
func (m *Manager) SealedSetting(ctx context.Context, key, fallback string) (string, error) {
	stored, err := m.db.ServerSetting(ctx, key, "")
	if err != nil {
		return fallback, err
	}
	if stored == "" {
		return fallback, nil
	}

	blob, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return fallback, fmt.Errorf("vault: setting %q is unreadable: %w", key, err)
	}

	var out string
	err = m.withRoot(func(root *crypto.Key) error {
		plain, err := crypto.OpenSealedSetting(root, sealedSettingDomain, key, blob)
		if err != nil {
			return fmt.Errorf("vault: opening setting %q: %w", key, err)
		}
		out = string(plain)
		return nil
	})
	if err != nil {
		return fallback, err
	}
	return out, nil
}

// SetSealedSetting stores a setting encrypted, or clears it when given an
// empty value.
func (m *Manager) SetSealedSetting(ctx context.Context, key, value string) error {
	if value == "" {
		return m.db.SetServerSetting(ctx, key, "")
	}
	return m.withRoot(func(root *crypto.Key) error {
		blob, err := crypto.SealSetting(root, sealedSettingDomain, key, []byte(value))
		if err != nil {
			return fmt.Errorf("vault: sealing setting %q: %w", key, err)
		}
		return m.db.SetServerSetting(ctx, key, base64.StdEncoding.EncodeToString(blob))
	})
}
