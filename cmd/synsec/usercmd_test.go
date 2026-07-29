package main

import (
	"os"
	"sync"
	"testing"
)

// Two prompts over one pipe.
//
// A provisioning script sends the password and its confirmation on two lines.
// A fresh buffered reader per prompt takes more than the line it returns, so
// the second prompt met EOF and every scripted account creation failed - the
// case the piped path exists for in the first place.
func TestTwoPromptsReadFromOnePipe(t *testing.T) {
	stdin, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	go func() {
		w.WriteString("premier-mot-de-passe\nsecond-mot-de-passe\n") //nolint:errcheck // the reader is what is under test
		w.Close()
	}()

	original := os.Stdin
	os.Stdin = stdin
	pipedOnce = sync.Once{}
	piped = nil
	t.Cleanup(func() {
		os.Stdin = original
		pipedOnce = sync.Once{}
		piped = nil
	})

	first, err := promptPassword("")
	if err != nil {
		t.Fatalf("first prompt: %v", err)
	}
	second, err := promptPassword("")
	if err != nil {
		t.Fatalf("second prompt: %v", err)
	}

	if first != "premier-mot-de-passe" {
		t.Errorf("the first prompt read %q", first)
	}
	if second != "second-mot-de-passe" {
		t.Errorf("the second prompt read %q, the confirmation was lost", second)
	}
}
