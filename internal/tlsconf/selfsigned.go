// Package tlsconf produces the certificate SYNSEC serves with.
//
// A household has no certificate authority and no public DNS name, so SYNSEC
// generates a single self-signed certificate that the owner installs in the
// machine's trust store with `synsec cert trust`.
//
// One certificate, not an authority signing a server certificate. The
// two-level chain is the textbook shape and it fails on Windows: Schannel
// checks whether the server certificate has been revoked, an offline authority
// publishes neither a revocation list nor an OCSP responder, and Windows
// Server treats "cannot determine" as a refusal. The handshake dies with
// CRYPT_E_NO_REVOCATION_CHECK, which reaches the server as a bare EOF and says
// nothing about what went wrong.
//
// Windows excludes the root of a chain from revocation checking. With a chain
// one certificate deep, there is nothing left to check and the problem
// disappears. This was verified against Windows Server 2022: identical
// requests fail without curl's --ssl-no-revoke and succeed with it.
package tlsconf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// validity is deliberately long.
//
// Nobody renews a certificate on a box in a cupboard. Something that expired
// quietly would take the heating with it and leave no clue why. The
// certificate is trusted by explicit installation rather than by a public
// authority, so its lifetime buys an attacker nothing.
const validity = 10 * 365 * 24 * time.Hour

// File names inside the data directory.
const (
	certName = "synsec.crt"
	keyName  = "synsec.key"
)

// Local describes the certificate SYNSEC is serving with.
type Local struct {
	// Certificate is what the server presents.
	Certificate tls.Certificate

	// TrustPath is the file to install in the machine's trust store. It is
	// the only file the owner ever needs to touch, and the only one that may
	// be copied to other machines.
	TrustPath string

	// Fingerprint is shown at setup so the owner can compare it against what
	// the browser or Windows displays.
	Fingerprint string

	// Fresh reports whether the certificate was created during this call.
	Fresh bool
}

// TrustPath returns the certificate to install, for callers that have only the
// data directory.
func TrustPath(dir string) string { return filepath.Join(dir, certName) }

// EnsureLocal loads the certificate, creating one if it is missing, unreadable
// or no longer covers how this machine is reached.
func EnsureLocal(dir string) (Local, error) {
	certPath := filepath.Join(dir, certName)
	keyPath := filepath.Join(dir, keyName)

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && usable(cert) {
		return describe(cert, certPath, false)
	}

	cert, err := generate(certPath, keyPath)
	if err != nil {
		return Local{}, err
	}
	return describe(cert, certPath, true)
}

func describe(cert tls.Certificate, certPath string, fresh bool) (Local, error) {
	if len(cert.Certificate) == 0 {
		return Local{}, fmt.Errorf("tlsconf: certificate is empty")
	}
	return Local{
		Certificate: cert,
		TrustPath:   certPath,
		Fingerprint: fingerprintOf(cert.Certificate[0]),
		Fresh:       fresh,
	}, nil
}

func generate(certPath, keyPath string) (tls.Certificate, error) {
	// RSA 2048 rather than an elliptic curve: slower to generate, once, and
	// accepted by every client that might ever talk to a home server,
	// including the .NET Framework that Windows PowerShell runs on.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsconf: generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsconf: generating serial: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "SYNSEC",
			Organization: []string{"SYNSEC"},
		},
		// Backdated an hour so a machine whose clock lags slightly - a
		// Raspberry Pi with no battery-backed clock, typically - does not
		// reject a certificate generated moments earlier.
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(validity),

		// Both a root and the server certificate. Unusual, and required here:
		// Windows only accepts a certificate as a trusted root if it declares
		// itself an authority, and only skips revocation checking for the root
		// of the chain. See the package comment.
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	template.DNSNames, template.IPAddresses = localNames()

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsconf: creating certificate: %w", err)
	}

	// 0644 on the certificate: it gets copied to the other machines on the
	// network, and contains nothing secret.
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsconf: encoding key: %w", err)
	}
	// 0600: a private key is as sensitive as anything else here.
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return tls.Certificate{}, err
	}

	return tls.LoadX509KeyPair(certPath, keyPath)
}

// usable reports whether an existing certificate still covers the addresses
// this machine answers on.
//
// A server that changed address would otherwise keep presenting a certificate
// that no longer matches how anyone reaches it, and the failure would look
// like a trust problem rather than a stale file.
func usable(cert tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	if !parsed.IsCA {
		// Left over from an earlier layout; it would be rejected by Windows.
		return false
	}
	if time.Now().After(parsed.NotAfter) {
		return false
	}

	_, ips := localNames()
	for _, ip := range ips {
		if parsed.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}

// localNames collects every name and address this machine answers to, so the
// certificate stays valid whether the owner types the hostname, an address, or
// localhost.
func localNames() ([]string, []net.IP) {
	names := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	if host, err := os.Hostname(); err == nil && host != "" {
		names = append(names, host, host+".local")
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return names, ips
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Loopback is already covered; link-local, multicast and unspecified
		// addresses are not how anyone reaches a server and only pad the
		// certificate.
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		ips = append(ips, ip)
	}
	return names, ips
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("tlsconf: creating %s: %w", dir, err)
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("tlsconf: writing %s: %w", path, err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("tlsconf: encoding %s: %w", path, err)
	}
	return f.Sync()
}

// Fingerprint returns the SHA-256 fingerprint of a certificate, in the
// colon-separated form browsers and Windows both display.
func Fingerprint(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("tlsconf: certificate is empty")
	}
	return fingerprintOf(cert.Certificate[0]), nil
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	const hex = "0123456789ABCDEF"

	out := make([]byte, 0, len(sum)*3)
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[b>>4], hex[b&0x0F])
	}
	return string(out)
}

// ServedNames lists the names and addresses a certificate says this server
// answers to.
//
// It exists so the interface can tell an address it really serves from one a
// caller merely claimed in a Host header. That header is chosen by whoever
// sends the request, and it ends up in a command the person is invited to
// paste - a command that carries a service token.
func ServedNames(cert tls.Certificate) []string {
	if len(cert.Certificate) == 0 {
		return nil
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}

	out := make([]string, 0, len(parsed.DNSNames)+len(parsed.IPAddresses))
	out = append(out, parsed.DNSNames...)
	for _, ip := range parsed.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
