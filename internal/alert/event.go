package alert

import (
	"time"
)

// Event is one thing worth telling somebody about.
//
// The field names are the contract: whatever receives this - Home Assistant,
// ntfy, a shell script behind a reverse proxy - reads them by name, and
// renaming one silently breaks somebody's automation. They are English and
// stable for that reason, while Summary carries the sentence a human reads.
type Event struct {
	Kind     Kind      `json:"kind"`
	Severity string    `json:"severity"`
	At       time.Time `json:"at"`
	Summary  string    `json:"summary"`

	// Actor is who did it: an account name, a device name, or empty when the
	// server acted on its own.
	Actor     string `json:"actor,omitempty"`
	ActorKind string `json:"actor_kind,omitempty"`
	// Vault and Target name what it was done to. The webhook goes to the
	// owner's own machine, not to a third party, so it carries the names: an
	// alert saying "a secret somewhere was refused" is one nobody can act on.
	Vault  string `json:"vault,omitempty"`
	Target string `json:"target,omitempty"`
	IP     string `json:"ip,omitempty"`
	Detail string `json:"detail,omitempty"`

	// Count is how many identical events this one stands for. One unless a
	// burst was folded into a single line, which is what a scan produces.
	Count int `json:"count"`

	// severity kept in its comparable form for the level filter; the JSON
	// carries the word.
	sev Severity
}

// message is what a webhook receives.
type message struct {
	Server string    `json:"server"`
	SentAt time.Time `json:"sent_at"`
	// Test marks a message sent by the "try it" button rather than by
	// something happening. A receiver that pages somebody at night should be
	// able to tell the difference.
	Test   bool    `json:"test,omitempty"`
	Events []Event `json:"events"`
}

// Values never appear in any of this. The journal does not hold them either,
// so there is nothing to leak here by accident - but a test asserts it, because
// "there is nothing to leak" is exactly the kind of statement that stops being
// true one careless field at a time.
