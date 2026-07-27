// Package api serves the REST interface that devices talk to.
//
// Routing uses the standard library's method-aware ServeMux, which has been
// able to express "GET /api/v1/secrets" since Go 1.22. A third-party router
// would add a dependency to the most exposed surface in SYNSEC for the sake of
// a handful of routes.
package api

import (
	"net/http"
	"time"

	"synsec/internal/vault"
)

// Version is the API version this server speaks, and the prefix every route
// carries.
const Version = "v1"

// Server holds everything the handlers need.
type Server struct {
	vault *vault.Manager
	now   func() time.Time

	// trustProxyHeaders decides whether X-Forwarded-For is believed.
	//
	// It defaults to false, and that default is load-bearing: token IP
	// allowlists are enforced against the address this yields, and anyone can
	// put anything in an X-Forwarded-For header. Trusting it without a proxy
	// in front would turn the allowlist into decoration.
	trustProxyHeaders bool
}

// Option configures a Server.
type Option func(*Server)

// TrustProxyHeaders makes the server believe X-Forwarded-For. Only enable it
// when SYNSEC genuinely sits behind a reverse proxy that overwrites the header.
func TrustProxyHeaders() Option {
	return func(s *Server) { s.trustProxyHeaders = true }
}

// withClock replaces the clock, for tests.
func withClock(now func() time.Time) Option {
	return func(s *Server) { s.now = now }
}

// New builds a server over an unsealed vault manager.
func New(v *vault.Manager, opts ...Option) *Server {
	s := &Server{vault: v, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Handler returns the routed, wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Liveness, deliberately unauthenticated and deliberately mute about
	// anything beyond whether the server is up and whether it is sealed.
	mux.HandleFunc("GET /api/"+Version+"/health", s.health)

	// One entry at a time. There is deliberately no endpoint that returns a
	// set of values: a secret is a single thing, asked for by name.
	mux.HandleFunc("GET /api/"+Version+"/secrets", s.withToken(s.listSecrets))
	mux.HandleFunc("GET /api/"+Version+"/secrets/value", s.withToken(s.getSecret))
	mux.HandleFunc("PUT /api/"+Version+"/secrets/value", s.withToken(s.putSecret))
	mux.HandleFunc("DELETE /api/"+Version+"/secrets/value", s.withToken(s.deleteSecret))

	return recoverPanics(securityHeaders(mux))
}

// health reports whether the server is running and whether it can serve
// secrets. It says nothing else: an unauthenticated endpoint is not the place
// to disclose the version, the vault names or the host.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	status := "ready"
	if s.vault.Sealed() {
		status = "sealed"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}
