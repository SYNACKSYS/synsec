package api

import (
	"log"
	"net/http"
	"strings"

	"synsec/internal/auth"
	"synsec/internal/store"
)

// tokenHandler is a handler that has already been given an authenticated,
// live, in-scope service token.
type tokenHandler func(w http.ResponseWriter, r *http.Request, tok store.ServiceToken)

// withToken authenticates a service token and hands it to the handler.
//
// Every failure answers 401 with the same body. Telling a caller apart -
// "unknown token" from "revoked" from "wrong secret" from "your address is not
// allowed" - would let anyone probe which tokens exist. The distinctions all
// survive in the audit log, where they belong.
func (s *Server) withToken(h tokenHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.vault.Sealed() {
			writeError(w, http.StatusServiceUnavailable, codeSealed,
				"the server is sealed and cannot serve secrets")
			return
		}

		tok, ok := s.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="synsec"`)
			writeError(w, http.StatusUnauthorized, codeUnauthorized, "invalid token")
			return
		}

		// Recording use is best-effort: a device must still get its secrets if
		// the bookkeeping write fails.
		if err := s.vault.DB().TouchServiceToken(r.Context(), tok.ID, s.now()); err != nil {
			log.Printf("api: recording use of token %s: %v", tok.ID, err)
		}
		h(w, r, tok)
	}
}

// authenticate resolves the bearer token on a request.
func (s *Server) authenticate(r *http.Request) (store.ServiceToken, bool) {
	raw, ok := bearerToken(r)
	if !ok {
		return store.ServiceToken{}, false
	}

	id, secret, err := auth.ParseServiceToken(raw)
	if err != nil {
		return store.ServiceToken{}, false
	}

	tok, hash, err := s.vault.DB().ServiceToken(r.Context(), id)
	if err != nil {
		return store.ServiceToken{}, false
	}
	if !auth.VerifyTokenSecret(secret, hash) {
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorToken, ActorID: id, ActorLabel: tok.Name,
			Action: "auth.failed", Detail: "wrong secret",
		})
		return store.ServiceToken{}, false
	}
	if !tok.Live(s.now()) {
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorToken, ActorID: id, ActorLabel: tok.Name,
			Action: "auth.failed", Detail: "revoked or expired",
		})
		return store.ServiceToken{}, false
	}
	if !tok.AllowsIP(s.clientIP(r)) {
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorToken, ActorID: id, ActorLabel: tok.Name,
			Action: "auth.failed", Detail: "address not in the allowlist",
		})
		return store.ServiceToken{}, false
	}
	return tok, true
}

// bearerToken pulls the credential out of the request.
//
// The Authorization header is the documented way. A query parameter is
// deliberately not accepted: it would end up in proxy logs and browser
// history, which is precisely where a secret must not be.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

// clientIP returns the address to enforce allowlists against.
func (s *Server) clientIP(r *http.Request) string {
	return s.clients.From(r)
}

// audit appends an entry, filling in the client address. Failures are logged
// rather than returned: losing a log line must not fail a request that would
// otherwise have succeeded.
func (s *Server) audit(r *http.Request, e store.AuditEntry) {
	e.At = s.now()
	e.IP = s.clientIP(r)
	if err := s.vault.DB().AppendAudit(r.Context(), e); err != nil {
		log.Printf("api: appending audit entry %q: %v", e.Action, err)
	}
}

// auditToken is audit for a request that authenticated successfully.
func (s *Server) auditToken(r *http.Request, tok store.ServiceToken, action, target, detail string) {
	s.audit(r, store.AuditEntry{
		ActorKind:  store.ActorToken,
		ActorID:    tok.ID,
		ActorLabel: tok.Name,
		Action:     action,
		Target:     target,
		Detail:     detail,
		// A device is tied to one vault, so every line it writes belongs to
		// that vault - including the refusals, which is exactly what somebody
		// looking at a secret's page wants to see.
		ProjectID: tok.ProjectID,
	})
}
