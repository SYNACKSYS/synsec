package unseal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestKeyfileRoundTrip(t *testing.T) {
	k := Keyfile{Path: filepath.Join(t.TempDir(), "root.key")}
	want := bytes.Repeat([]byte{0xA5}, 32)

	handle, err := k.Protect(want)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	got, err := k.Expose(handle)
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("key material changed across the round trip")
	}
}

// Re-sealing to this host is a normal step after recovering onto a new
// machine, so a second Protect must replace the key rather than refuse.
func TestKeyfileReplacesExistingKey(t *testing.T) {
	dir := t.TempDir()
	k := Keyfile{Path: filepath.Join(dir, "root.key")}

	if _, err := k.Protect(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("first Protect: %v", err)
	}
	want := bytes.Repeat([]byte{2}, 32)
	handle, err := k.Protect(want)
	if err != nil {
		t.Fatalf("second Protect: %v", err)
	}

	got, err := k.Expose(handle)
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the second Protect did not replace the stored key")
	}

	// The temporary file used for the atomic rename must not survive.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d files left in the key directory, want only root.key", len(entries))
	}
}

func TestKeyfileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows; DPAPI is used there")
	}
	k := Keyfile{Path: filepath.Join(t.TempDir(), "root.key")}
	if _, err := k.Protect(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("Protect: %v", err)
	}

	info, err := os.Stat(k.Path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode is %04o, want 0600", perm)
	}
}

func TestKeyfileMissingReportsNoHandle(t *testing.T) {
	k := Keyfile{Path: filepath.Join(t.TempDir(), "absent.key")}
	if _, err := k.Expose(nil); !errors.Is(err, ErrNoHandle) {
		t.Fatalf("Expose of a missing key file returned %v, want ErrNoHandle", err)
	}
}

// The fallback must never claim protection it does not provide: the setup
// wizard keys its warning off this flag.
func TestKeyfileAdmitsItsWeakness(t *testing.T) {
	p := Keyfile{}.Protection()
	if p.ResistsDiskTheft {
		t.Fatal("keyfile provider claims to resist disk theft")
	}
	if p.Caveat == "" {
		t.Fatal("keyfile provider offers no caveat for the setup wizard to display")
	}
}
