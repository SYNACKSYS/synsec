package tlsconf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func ensure(t *testing.T, dir string) Local {
	t.Helper()
	local, err := EnsureLocal(dir)
	if err != nil {
		t.Fatalf("EnsureLocal: %v", err)
	}
	return local
}

func parsed(t *testing.T, local Local) *x509.Certificate {
	t.Helper()
	if len(local.Certificate.Certificate) == 0 {
		t.Fatal("the certificate is empty")
	}
	cert, err := x509.ParseCertificate(local.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}

func TestGeneratesThenReuses(t *testing.T) {
	dir := t.TempDir()

	first := ensure(t, dir)
	if !first.Fresh {
		t.Fatal("the first call did not report a freshly created certificate")
	}

	second := ensure(t, dir)
	if second.Fresh {
		t.Fatal("the second call regenerated instead of reusing")
	}
	// Regenerating on every start would undo the trust the owner installed
	// and bring the browser warning back each time.
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("the certificate changed between two starts")
	}
}

// The chain must be exactly one certificate deep.
//
// Windows skips revocation checking only for the root of a chain. A separate
// authority signing a server certificate leaves a leaf whose revocation status
// Schannel demands and no offline authority can supply, and the handshake
// fails with CRYPT_E_NO_REVOCATION_CHECK.
func TestChainIsASingleCertificate(t *testing.T) {
	local := ensure(t, t.TempDir())

	if n := len(local.Certificate.Certificate); n != 1 {
		t.Fatalf("the server presents a chain %d certificates deep, want 1", n)
	}
}

// Windows only accepts a certificate as a trusted root if it declares itself
// an authority, so this flag is what makes `synsec cert trust` work at all.
func TestCertificateIsSelfSignedRoot(t *testing.T) {
	local := ensure(t, t.TempDir())
	cert := parsed(t, local)

	if !cert.IsCA {
		t.Fatal("the certificate does not declare itself an authority")
	}
	if !cert.BasicConstraintsValid {
		t.Fatal("the certificate has no basic constraints")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("the certificate is not self-signed: %v", err)
	}
	// It has to serve as a server certificate too, or Schannel will not use it
	// for a TLS server.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("the extended key usage is %v, want server authentication", cert.ExtKeyUsage)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("the certificate cannot sign a handshake")
	}
}

func TestVerifiesAgainstItself(t *testing.T) {
	local := ensure(t, t.TempDir())
	cert := parsed(t, local)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("the certificate does not verify once installed as a root: %v", err)
	}
}

func TestCertificateCoversLocalNames(t *testing.T) {
	local := ensure(t, t.TempDir())
	cert := parsed(t, local)

	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := cert.VerifyHostname(name); err != nil {
			t.Errorf("the certificate does not cover %s: %v", name, err)
		}
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		if err := cert.VerifyHostname(host); err != nil {
			t.Errorf("the certificate does not cover the machine name %q: %v", host, err)
		}
	}
}

// A certificate that expires quietly would take the house down with it.
func TestCertificateOutlivesTheHardware(t *testing.T) {
	local := ensure(t, t.TempDir())
	cert := parsed(t, local)

	if remaining := time.Until(cert.NotAfter); remaining < 5*365*24*time.Hour {
		t.Fatalf("the certificate expires in %v, too soon to be forgotten about", remaining)
	}
	if !cert.NotBefore.Before(time.Now()) {
		t.Fatal("the certificate is not yet valid on the machine that made it")
	}
}

func TestPrivateKeyIsNotReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	ensure(t, dir)

	info, err := os.Stat(filepath.Join(dir, keyName))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the private key is mode %04o, want 0600", perm)
	}
}

// The certificate gets copied to the other machines on the network, so it must
// stay readable.
func TestCertificateIsReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	ensure(t, dir)

	info, err := os.Stat(TrustPath(dir))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("the certificate is mode %04o, want 0644", perm)
	}
}

func TestRegeneratesWhenUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(TrustPath(dir), []byte("ceci n'est pas un certificat"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	local, err := EnsureLocal(dir)
	if err != nil {
		t.Fatalf("EnsureLocal over a broken certificate: %v", err)
	}
	if !local.Fresh {
		t.Fatal("a broken certificate was reported as reused")
	}
}

// A certificate left over from the earlier two-level layout is an ordinary
// leaf, which Windows refuses as a trusted root. It has to be replaced rather
// than reused, silently and without the owner having to know why.
func TestReplacesANonRootCertificate(t *testing.T) {
	dir := t.TempDir()
	writeLeafCertificate(t, dir)

	local, err := EnsureLocal(dir)
	if err != nil {
		t.Fatalf("EnsureLocal: %v", err)
	}
	if !local.Fresh {
		t.Fatal("a non-root certificate was reused instead of being replaced")
	}
	if cert := parsed(t, local); !cert.IsCA {
		t.Fatal("the replacement is still not a root")
	}
}

// writeLeafCertificate puts a valid but non-root certificate in place, of the
// shape the two-level layout used to produce.
func writeLeafCertificate(t *testing.T, dir string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SYNSEC"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	template.DNSNames, template.IPAddresses = localNames()

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if err := writePEM(TrustPath(dir), "CERTIFICATE", der, 0o644); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	if err := writePEM(filepath.Join(dir, keyName), "PRIVATE KEY", keyDER, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
}

func TestFingerprintShape(t *testing.T) {
	local := ensure(t, t.TempDir())

	// The owner compares this against what the browser and Windows display, so
	// it has to be in the same colon-separated hexadecimal form.
	parts := strings.Split(local.Fingerprint, ":")
	if len(parts) != 32 {
		t.Fatalf("the fingerprint has %d groups, want 32: %s", len(parts), local.Fingerprint)
	}
	for _, p := range parts {
		if len(p) != 2 {
			t.Fatalf("group %q is not two characters: %s", p, local.Fingerprint)
		}
	}

	got, err := Fingerprint(local.Certificate)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got != local.Fingerprint {
		t.Fatal("Fingerprint disagrees with the fingerprint reported by EnsureLocal")
	}
}
