package auth

import (
	"sync"
	"testing"
	"time"

	"synsec/internal/crypto"
)

// Derivation is memory-hard on purpose. Unbounded, that cost is a weapon: a
// few dozen simultaneous sign-in attempts would ask for more memory than the
// machines SYNSEC targets have.
func TestDerivationsAreBounded(t *testing.T) {
	if got := DerivationSlots(); got < 2 || got > 4 {
		t.Fatalf("%d derivations may run at once, want between 2 and 4", got)
	}
}

// Under load, callers wait rather than all allocating at once, and the work
// still completes.
func TestConcurrentDerivationsAllComplete(t *testing.T) {
	light := crypto.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}
	cred, err := HashPasswordWith("correct horse battery", light)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}

	const callers = 24
	var wg sync.WaitGroup
	results := make(chan bool, callers)

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := VerifyPasswordBusy(cred, "correct horse battery")
			results <- err == nil && ok
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("derivations did not finish: the queue is not draining")
	}
	close(results)

	for ok := range results {
		if !ok {
			t.Fatal("a caller was refused or got the wrong answer under load")
		}
	}
}
