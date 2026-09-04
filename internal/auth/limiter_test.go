package auth

import (
	"errors"
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
//
// The number of callers is read from the waiting room rather than written as a
// constant. A constant encodes an assumption about the machine: the room is
// sized from the core count, so twenty-four callers fit on a laptop and
// overflow a two-core server, and the test then fails for a reason that has
// nothing to do with what it is checking. Found exactly that way, on a small
// virtual machine.
func TestConcurrentDerivationsAllComplete(t *testing.T) {
	light := crypto.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}
	cred, err := HashPasswordWith("correct horse battery", light)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}

	callers := waitingRoom()
	var wg sync.WaitGroup
	results := make(chan bool, callers)
	t.Logf("%d appelants, pour une salle d'attente de %d places", callers, waitingRoom())

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

// waitingRoom is how many callers may be parked at once, slots included.
//
// Exported nowhere: this is the shape of the queue, not a promise to anyone
// outside the package.
func waitingRoom() int {
	DerivationSlots() // force l'initialisation
	return cap(queued)
}

// Beyond the waiting room, a caller is turned away at once rather than parked.
//
// C'est la moitié de la promesse que l'autre test ne couvre pas : une file
// bornée ne sert à rien si le dépassement se traduit par une attente sans fin
// ou par une mauvaise réponse. Sur une machine à deux cœurs, la salle tient
// seize places, et la dix-septième connexion simultanée doit repartir avec un
// refus propre.
func TestBeyondTheWaitingRoomCallersAreRefused(t *testing.T) {
	light := crypto.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}
	cred, err := HashPasswordWith("correct horse battery", light)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}

	// Deux fois la capacité : le dépassement est certain, quelle que soit la
	// machine.
	callers := waitingRoom() * 2
	var wg sync.WaitGroup
	refusals := make(chan error, callers)

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := VerifyPasswordBusy(cred, "correct horse battery")
			refusals <- err
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("le dépassement n'a pas rendu la main : la file ne se vide pas")
	}
	close(refusals)

	var busy, autres int
	for err := range refusals {
		switch {
		case err == nil:
		case errors.Is(err, ErrBusy):
			busy++
		default:
			autres++
			t.Errorf("refus inattendu : %v", err)
		}
	}
	if busy == 0 {
		t.Fatalf("%d appelants pour %d places, et aucun refus", callers, waitingRoom())
	}
	t.Logf("%d refus propres sur %d appelants", busy, callers)
}
