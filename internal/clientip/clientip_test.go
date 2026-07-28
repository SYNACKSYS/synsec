package clientip

import (
	"net/http"
	"testing"
)

func request(remote, forwarded string) *http.Request {
	r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
	if forwarded != "" {
		r.Header.Set("X-Forwarded-For", forwarded)
	}
	return r
}

// With no proxy named, the header is worthless: believing it would let any
// caller choose the address its allowlist is checked against.
func TestForwardedHeaderIgnoredWithoutTrustedProxies(t *testing.T) {
	r, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := r.From(request("203.0.113.9:1234", "10.0.0.1")); got != "203.0.113.9" {
		t.Fatalf("got %q, want the connection's own address", got)
	}
}

func TestForwardedHeaderReadFromATrustedProxy(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := r.From(request("10.0.0.1:1234", "203.0.113.9")); got != "203.0.113.9" {
		t.Fatalf("got %q, want the forwarded client", got)
	}
}

// The chain is walked from the right. Reading the left-most entry, as most
// examples do, would let a caller prepend whatever address it liked.
func TestSpoofedEntriesArePrependedAndIgnored(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The attacker sets "1.2.3.4"; the proxy appends the real address.
	got := r.From(request("10.0.0.1:1234", "1.2.3.4, 203.0.113.9"))
	if got != "203.0.113.9" {
		t.Fatalf("got %q: a prepended address was believed", got)
	}
}

// Several proxies of ours in a row are skipped until a caller appears.
func TestOwnProxiesAreSkipped(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8", "192.168.1.1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.From(request("10.0.0.1:1234", "203.0.113.9, 192.168.1.1, 10.0.0.2"))
	if got != "203.0.113.9" {
		t.Fatalf("got %q, want the address behind our own hops", got)
	}
}

// A request arriving from somewhere that is not a trusted proxy keeps its own
// address, whatever it claims.
func TestUntrustedSenderCannotForge(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := r.From(request("203.0.113.9:1234", "127.0.0.1")); got != "203.0.113.9" {
		t.Fatalf("got %q: an untrusted sender forged its address", got)
	}
}

// A typo in the configuration disables the protection it configures, so it is
// reported instead of dropped.
func TestMalformedProxyIsReported(t *testing.T) {
	if _, err := New([]string{"pas-une-adresse"}); err == nil {
		t.Fatal("a malformed entry was accepted")
	}
	if _, err := New([]string{"10.0.0.0/8", ""}); err != nil {
		t.Fatalf("an empty entry should be skipped: %v", err)
	}
}
