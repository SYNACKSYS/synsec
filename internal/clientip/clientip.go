// Package clientip decides which address a request really came from.
//
// It exists because the answer governs three things that matter: the sign-in
// throttle, the per-token address allowlists, and what the audit log records.
// Getting it wrong in either direction is bad. Trust the forwarded header
// blindly and every caller picks its own address; ignore it behind a proxy and
// every caller looks like the proxy.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// Resolver answers "who is calling" for one server's deployment.
type Resolver struct {
	// trusted are the addresses whose X-Forwarded-For is believed. Empty means
	// the header is ignored entirely, which is the default and the only safe
	// setting for a server reached directly.
	trusted []string
}

// New builds a resolver. Entries are addresses or CIDR blocks; anything
// unparseable is reported rather than silently dropped, because a typo here
// quietly disables the protection it was meant to configure.
func New(trustedProxies []string) (*Resolver, error) {
	r := &Resolver{}
	for _, raw := range trustedProxies {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if err := validate(entry); err != nil {
			return nil, err
		}
		r.trusted = append(r.trusted, entry)
	}
	return r, nil
}

// TrustsAnyone reports whether a resolver was given no proxies, in which case
// the forwarded header is ignored.
func (r *Resolver) TrustsAnyone() bool { return len(r.trusted) == 0 }

// From returns the address to hold the caller to.
//
// With no trusted proxy, that is the connection's own address and nothing
// else. With trusted proxies, the forwarded chain is walked from the right,
// discarding hops that are themselves trusted, and the first address that is
// not is the caller. Reading the left-most entry instead - as most examples
// do - would let anyone prepend whatever address they liked.
func (r *Resolver) From(req *http.Request) string {
	direct := remoteHost(req)
	if len(r.trusted) == 0 || !r.contains(direct) {
		return direct
	}

	forwarded := req.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return direct
	}

	hops := strings.Split(forwarded, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		if r.contains(hop) {
			continue // another proxy of ours
		}
		return hop
	}
	return direct
}

func (r *Resolver) contains(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	for _, entry := range r.trusted {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		if other := net.ParseIP(entry); other != nil {
			if v4 := other.To4(); v4 != nil {
				other = v4
			}
			if other.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func remoteHost(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func validate(entry string) error {
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return nil
	}
	if net.ParseIP(entry) != nil {
		return nil
	}
	return &net.AddrError{Err: "ni une adresse IP ni un bloc CIDR", Addr: entry}
}
