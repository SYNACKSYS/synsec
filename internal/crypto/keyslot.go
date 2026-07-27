package crypto

import (
	"errors"
	"fmt"
)

// SlotKind describes how a slot's wrapping key is obtained.
type SlotKind string

const (
	// SlotPassphrase is unsealed by a human typing a passphrase.
	SlotPassphrase SlotKind = "passphrase"

	// SlotRecovery is unsealed by the printed recovery code handed out during
	// setup. It exists so that a forgotten passphrase is an inconvenience
	// rather than the permanent loss of every secret.
	SlotRecovery SlotKind = "recovery"

	// SlotMachine is unsealed by the host itself - DPAPI on Windows, a TPM via
	// systemd-creds on Linux, or a keyfile as a last resort. This is the slot
	// that lets SYNSEC start unattended at boot.
	SlotMachine SlotKind = "machine"
)

// ErrSlotMismatch means the supplied secret does not open this slot.
var ErrSlotMismatch = errors.New("crypto: wrong secret for this key slot")

// A KeySlot holds one independently wrapped copy of the root key, in the
// spirit of LUKS key slots. Any single slot can unseal the server, and slots
// can be added or revoked without ever re-encrypting a secret - only the small
// wrapped blobs change.
type KeySlot struct {
	ID     string       `json:"id"`
	Kind   SlotKind     `json:"kind"`
	Salt   []byte       `json:"salt,omitempty"`
	Params Argon2Params `json:"params,omitempty"`
	Blob   []byte       `json:"blob"`
}

// slotAAD binds a wrapped root key to the identity of its slot, so a blob
// cannot be transplanted from, say, a revoked passphrase slot into the machine
// slot by someone with write access to the database.
func slotAAD(id string, kind SlotKind) []byte {
	return bindAAD("synsec/slot/v1", id, string(kind))
}

// NewSecretSlot wraps root under a key derived from a human secret: a
// passphrase, or the recovery code produced at setup.
func NewSecretSlot(id string, kind SlotKind, root *Key, secret []byte, p Argon2Params) (*KeySlot, error) {
	if kind != SlotPassphrase && kind != SlotRecovery {
		return nil, fmt.Errorf("crypto: %q slots are not derived from a secret", kind)
	}
	if len(secret) == 0 {
		return nil, errors.New("crypto: empty secret")
	}
	salt, err := NewSalt()
	if err != nil {
		return nil, err
	}
	wrapping, err := p.derive(secret, salt)
	if err != nil {
		return nil, err
	}
	defer wrapping.Zero()

	blob, err := seal(wrapping, slotAAD(id, kind), root.Bytes())
	if err != nil {
		return nil, err
	}
	return &KeySlot{ID: id, Kind: kind, Salt: salt, Params: p, Blob: blob}, nil
}

// NewMachineSlot wraps root under key material supplied by the host keystore.
// wrapping remains the caller's to zero.
func NewMachineSlot(id string, root, wrapping *Key) (*KeySlot, error) {
	blob, err := seal(wrapping, slotAAD(id, SlotMachine), root.Bytes())
	if err != nil {
		return nil, err
	}
	return &KeySlot{ID: id, Kind: SlotMachine, Blob: blob}, nil
}

// Unseal recovers the root key from a human secret.
func (s *KeySlot) Unseal(secret []byte) (*Key, error) {
	if s.Kind == SlotMachine {
		return nil, fmt.Errorf("crypto: machine slots unseal via UnsealWith")
	}
	wrapping, err := s.Params.derive(secret, s.Salt)
	if err != nil {
		return nil, err
	}
	defer wrapping.Zero()
	return s.unwrap(wrapping)
}

// UnsealWith recovers the root key from host-supplied key material.
func (s *KeySlot) UnsealWith(wrapping *Key) (*Key, error) {
	return s.unwrap(wrapping)
}

func (s *KeySlot) unwrap(wrapping *Key) (*Key, error) {
	raw, err := open(wrapping, slotAAD(s.ID, s.Kind), s.Blob)
	if err != nil {
		return nil, ErrSlotMismatch
	}
	return KeyFrom(raw)
}
