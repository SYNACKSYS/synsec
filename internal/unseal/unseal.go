// Package unseal obtains, without human intervention, the wrapping key that
// opens SYNSEC's machine key slot.
//
// This is what lets the server start on its own after a power cut. It is also
// the weakest link in the chain, so each provider states plainly what it does
// and does not protect against, and the setup wizard shows that verdict to the
// owner rather than implying a uniform level of security.
package unseal

import "errors"

// ErrNoHandle means no machine slot has been provisioned on this host yet.
var ErrNoHandle = errors.New("unseal: no machine key material stored on this host")

// Provider protects the wrapping key of the machine key slot using whatever
// facility the host offers.
type Provider interface {
	// Name identifies the provider in the configuration file and audit log.
	Name() string

	// Protection describes the guarantee actually obtained on this host.
	Protection() Protection

	// Protect seals key material, returning an opaque handle to persist
	// alongside the machine key slot.
	Protect(key []byte) (handle []byte, err error)

	// Expose recovers key material previously sealed by Protect.
	Expose(handle []byte) (key []byte, err error)
}

// Protection is an honest account of what a provider defends against.
//
// Summary and Caveat are shown verbatim in the web interface, hence French:
// they are aimed at the owner of the machine, not at a developer.
type Protection struct {
	// ResistsDiskTheft reports whether someone who walks off with the disk,
	// or with a copy of a backup, is left holding unusable ciphertext.
	ResistsDiskTheft bool

	// Summary is a one-line explanation for a non-technical owner.
	Summary string

	// Caveat, when non-empty, is a warning the setup wizard must display
	// prominently rather than bury in a log file.
	Caveat string
}
