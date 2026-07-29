package web

import (
	"net"
	"net/http"
	"strings"
)

// Which address the interface may repeat back.
//
// The Host header is chosen by whoever sends the request, and one page puts it
// straight into a command the person is invited to paste - a command carrying
// a freshly minted service token. Somebody able to set that header on a
// victim's request would have the page hand them the token itself.
//
// So the header is checked against the names the server's own certificate says
// it answers to. An address that is not among them is replaced rather than
// repeated: the command stays correct, and it points here.

// unknownHost stands in when nothing better is known, which only happens if
// the certificate carries no names at all.
const unknownHost = "ton-serveur"

// ServedNames tells the interface which addresses this server answers to,
// taken from its certificate. Empty leaves the Host header repeated as it
// arrives, which is the old behaviour and only reachable in tests.
func ServedNames(names []string) Option {
	return func(s *Server) {
		s.servedNames = make(map[string]bool, len(names))
		for _, n := range names {
			if n = strings.TrimSpace(strings.ToLower(n)); n != "" {
				s.servedNames[n] = true
			}
		}
		s.firstServedName = ""
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" {
				s.firstServedName = n
				break
			}
		}
	}
}

// publicHost returns the authority to show, which is the one the request
// claimed only when this server really answers to it.
func (s *Server) publicHost(r *http.Request) string {
	if len(s.servedNames) == 0 {
		return r.Host
	}

	name, port := splitHost(r.Host)
	if s.servedNames[strings.ToLower(name)] {
		return r.Host
	}

	// Not ours. Fall back to a name the certificate does cover, keeping the
	// port the connection came in on so the command still works as written.
	fallback := s.firstServedName
	if fallback == "" {
		fallback = unknownHost
	}
	if port != "" {
		return net.JoinHostPort(fallback, port)
	}
	return fallback
}

// splitHost separates a Host header into a name and a port, tolerating the
// absence of either and refusing a port that is not a number.
func splitHost(host string) (name, port string) {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host, ""
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return h, ""
		}
	}
	return h, p
}
