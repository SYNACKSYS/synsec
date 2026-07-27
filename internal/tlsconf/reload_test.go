package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a throwaway certificate and key, named after the common
// name so a test can tell one generation from the next.
func writePair(t *testing.T, dir, commonName string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	certPath = filepath.Join(dir, "synsec.crt")
	keyPath = filepath.Join(dir, "synsec.key")
	writeBlock(t, certPath, "CERTIFICATE", der)
	writeBlock(t, keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writeBlock(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// commonName reads back what a served certificate identifies itself as.
func commonName(t *testing.T, r *Reloader) string {
	t.Helper()
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return parsed.Subject.CommonName
}

// A renewal replaces the files on disk. The point of the reloader is that this
// takes effect without restarting the server.
func TestReloaderPicksUpARenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "avant")

	r, err := NewReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	if got := commonName(t, r); got != "avant" {
		t.Fatalf("the first certificate is %q", got)
	}

	writePair(t, dir, "apres")
	// The files are checked at most every ten seconds; a test cannot wait, so
	// the deadline is moved rather than the clock.
	r.mu.Lock()
	r.nextCheck = time.Now().Add(-time.Second)
	r.mu.Unlock()

	if got := commonName(t, r); got != "apres" {
		t.Fatalf("the renewed certificate was not picked up, still serving %q", got)
	}
}

// Renewal writes two files that are briefly out of step. A server that fell
// over on a half-written pair would turn a routine renewal into an outage.
func TestBrokenRenewalKeepsTheOldCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "valide")

	r, err := NewReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}

	// A certificate half-written, or truncated by a client that crashed.
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nincomple"), 0o600); err != nil {
		t.Fatalf("writing a broken certificate: %v", err)
	}
	r.mu.Lock()
	r.nextCheck = time.Now().Add(-time.Second)
	r.mu.Unlock()

	if got := commonName(t, r); got != "valide" {
		t.Fatalf("a broken renewal was served: %q", got)
	}

	// And a file that vanished entirely, as during an atomic replace.
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("removing the certificate: %v", err)
	}
	r.mu.Lock()
	r.nextCheck = time.Now().Add(-time.Second)
	r.mu.Unlock()

	if got := commonName(t, r); got != "valide" {
		t.Fatalf("a missing certificate took the server down to %q", got)
	}
}

// A wrong path is worth reporting at startup, not at the first connection an
// hour later.
func TestReloaderRefusesAMissingPair(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewReloader(filepath.Join(dir, "absent.crt"), filepath.Join(dir, "absent.key")); err == nil {
		t.Fatal("a missing certificate was accepted")
	}
}

// Between two checks the answer comes from memory, so a device reconnecting in
// a loop does not turn into two syscalls per attempt.
func TestReloaderDoesNotStatOnEveryHandshake(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "stable")

	r, err := NewReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}

	writePair(t, dir, "ignore")
	if got := commonName(t, r); got != "stable" {
		t.Fatalf("the files were re-read before the interval elapsed: %q", got)
	}
}
