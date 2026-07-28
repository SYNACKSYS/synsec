package auth

import (
	"errors"
	"runtime"
	"sync"
	"time"
)

// ErrBusy means the server is already deriving as many passwords as it will
// hold in memory at once.
var ErrBusy = errors.New("auth: too many password derivations at once")

// Password derivation is memory-hard on purpose: 64 MiB and four threads per
// attempt make guessing expensive. Unbounded, that same cost is a weapon.
// Twenty simultaneous sign-in attempts would ask for 1.3 GiB, which is more
// than the machines SYNSEC is built for have to spare.
//
// So derivations run a few at a time and the rest wait their turn. What this
// buys is that a flood slows sign-ins down instead of taking the server out,
// and the queue is bounded so the waiting itself cannot exhaust anything
// either.
var (
	limiterOnce sync.Once
	slots       chan struct{}
	queued      chan struct{}
)

// maxWait is how long a request may wait for a slot before being turned away.
//
// Long enough that a household never notices, short enough that a flood gets
// a refusal rather than a connection held open.
const maxWait = 5 * time.Second

func initLimiter() {
	// Two derivations per core, capped: the work is memory-bound rather than
	// CPU-bound, so more parallelism buys nothing and costs a great deal of
	// resident memory.
	concurrent := runtime.NumCPU()
	if concurrent < 2 {
		concurrent = 2
	}
	if concurrent > 4 {
		concurrent = 4
	}
	slots = make(chan struct{}, concurrent)

	// The waiting room is bounded too. Beyond it, requests are refused
	// immediately rather than parked, so a flood cannot turn into a pile of
	// goroutines each holding a connection.
	queued = make(chan struct{}, concurrent*8)
}

// withSlot runs fn while holding one of the derivation slots.
func withSlot[T any](fn func() (T, error)) (T, error) {
	limiterOnce.Do(initLimiter)

	var zero T
	select {
	case queued <- struct{}{}:
		defer func() { <-queued }()
	default:
		return zero, ErrBusy
	}

	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-timer.C:
		return zero, ErrBusy
	}

	return fn()
}

// DerivationSlots reports how many derivations may run at once, for tests and
// for the operator who wants to know.
func DerivationSlots() int {
	limiterOnce.Do(initLimiter)
	return cap(slots)
}
