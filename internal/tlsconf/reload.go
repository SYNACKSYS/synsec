package tlsconf

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// checkEvery bounds how often the files are stat'ed.
//
// A handshake is rare on a home server, but a device that reconnects in a loop
// should not turn into two syscalls per attempt. Ten seconds is far below any
// renewal interval and far above any plausible handshake rate.
const checkEvery = 10 * time.Second

// Reloader serves a certificate from disk and picks up its replacement without
// a restart.
//
// This exists for the renewal case. An ACME client rewrites the pair every
// sixty days, and a server that only read it at startup would go on presenting
// an expired certificate until somebody noticed - which, on a machine nobody
// logs into, means until something broke.
type Reloader struct {
	certPath string
	keyPath  string

	mu        sync.RWMutex
	cert      *tls.Certificate
	certMod   time.Time
	keyMod    time.Time
	nextCheck time.Time
}

// NewReloader loads the pair once and fails if it cannot, so a wrong path is
// reported at startup rather than at the first connection.
func NewReloader(certPath, keyPath string) (*Reloader, error) {
	r := &Reloader{certPath: certPath, keyPath: keyPath}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate answers a handshake, reloading first if the files changed.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, next := r.cert, r.nextCheck
	r.mu.RUnlock()

	if time.Now().Before(next) {
		return cert, nil
	}
	return r.refresh(), nil
}

// refresh reloads if the files moved, and returns what to serve.
//
// A failure here is logged and swallowed: the old certificate keeps working.
// Renewal writes two files that are briefly out of step with each other, and a
// server that fell over on a half-written pair would turn a routine renewal
// into an outage.
func (r *Reloader) refresh() *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextCheck = time.Now().Add(checkEvery)

	certMod, keyMod, err := modTimes(r.certPath, r.keyPath)
	if err != nil {
		log.Printf("tls: certificat illisible, l'ancien reste en service : %v", err)
		return r.cert
	}
	if certMod.Equal(r.certMod) && keyMod.Equal(r.keyMod) {
		return r.cert
	}

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		log.Printf("tls: nouveau certificat refusé, l'ancien reste en service : %v", err)
		return r.cert
	}

	r.cert, r.certMod, r.keyMod = &cert, certMod, keyMod
	log.Printf("tls: certificat rechargé depuis %s", r.certPath)
	return r.cert
}

// load reads the pair unconditionally, for the first load.
func (r *Reloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("lecture du certificat : %w", err)
	}
	certMod, keyMod, err := modTimes(r.certPath, r.keyPath)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cert, r.certMod, r.keyMod = &cert, certMod, keyMod
	r.nextCheck = time.Now().Add(checkEvery)
	return nil
}

func modTimes(certPath, keyPath string) (certMod, keyMod time.Time, err error) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("tls: %w", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("tls: %w", err)
	}
	return certInfo.ModTime(), keyInfo.ModTime(), nil
}
