package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"synsec/internal/store"
	"synsec/internal/vault"
)

// maxBodyBytes caps a write. A secret is a password or a key, not a payload,
// and the limit keeps an unauthenticated-sized mistake from becoming a
// memory problem on a small board.
const maxBodyBytes = 64 << 10

type secretSummary struct {
	Name      string    `json:"name"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Comment   string    `json:"comment,omitempty"`
}

type secretValue struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Version int64  `json:"version"`
}

type putSecretRequest struct {
	Value string `json:"value"`
}

// listSecrets returns the names of the secrets in the token's vault. No value
// is decrypted, so the response is safe to log.
//
// Names only, never values: nothing in the API hands back a set of secrets at
// once, so a device reads what it needs one entry at a time.
func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request, tok store.ServiceToken) {
	found, err := s.vault.DB().ListSecrets(r.Context(), tok.ProjectID, tok.Env)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	out := make([]secretSummary, 0, len(found))
	for _, sec := range found {
		// A narrowed token must not learn what else the vault holds: the
		// listing is the one place that would tell it.
		if !tok.AllowsSecret(sec.Name) {
			continue
		}
		out = append(out, secretSummary{
			Name:      sec.Name,
			Version:   sec.CurrentVersion,
			UpdatedAt: sec.UpdatedAt,
			Comment:   sec.Comment,
		})
	}

	s.auditToken(r, tok, "secret.list", "", "")
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

// getSecret returns one decrypted value.
func (s *Server) getSecret(w http.ResponseWriter, r *http.Request, tok store.ServiceToken) {
	name, ok := s.scopedName(w, r, tok, false)
	if !ok {
		return
	}

	loc := store.SecretLocation{ProjectID: tok.ProjectID, Env: tok.Env, Name: name}

	// Read once, used twice: the restriction hangs off the secret's row, and
	// so does the version number the answer reports.
	meta, err := s.vault.DB().SecretMeta(r.Context(), loc)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	if !s.addressAllowed(w, r, tok, meta.ID, name) {
		return
	}

	value, err := s.vault.GetSecret(r.Context(), loc)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	s.auditToken(r, tok, "secret.read", name, "")
	writeJSON(w, http.StatusOK, secretValue{
		Name: name, Value: string(value), Version: meta.CurrentVersion,
	})
}

// putSecret stores a new version of a secret, creating it if needed.
func (s *Server) putSecret(w http.ResponseWriter, r *http.Request, tok store.ServiceToken) {
	name, ok := s.scopedName(w, r, tok, true)
	if !ok {
		return
	}

	var body putSecretRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, "expected a JSON body with a value field")
		return
	}

	loc := store.SecretLocation{ProjectID: tok.ProjectID, Env: tok.Env, Name: name}
	if !s.addressAllowedFor(w, r, tok, loc, name) {
		return
	}

	sec, err := s.vault.PutSecret(r.Context(), loc, []byte(body.Value), "", "token:"+tok.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	// The value never enters the audit log - only the fact that it changed.
	s.auditToken(r, tok, "secret.write", name, "")
	writeJSON(w, http.StatusOK, secretValue{Name: name, Version: sec.CurrentVersion})
}

// deleteSecret removes a secret and its history.
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, tok store.ServiceToken) {
	name, ok := s.scopedName(w, r, tok, true)
	if !ok {
		return
	}

	loc := store.SecretLocation{ProjectID: tok.ProjectID, Env: tok.Env, Name: name}
	if !s.addressAllowedFor(w, r, tok, loc, name) {
		return
	}

	if err := s.vault.DB().DeleteSecret(r.Context(), loc); err != nil {
		s.fail(w, r, err)
		return
	}

	s.auditToken(r, tok, "secret.delete", name, "")
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

// addressAllowedFor looks the secret up and checks the caller's address.
//
// A name that does not exist yet has no restriction to check: creating an
// entry is not something an address list written for an older entry can
// govern.
func (s *Server) addressAllowedFor(w http.ResponseWriter, r *http.Request, tok store.ServiceToken, loc store.SecretLocation, name string) bool {
	meta, err := s.vault.DB().SecretMeta(r.Context(), loc)
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	return s.addressAllowed(w, r, tok, meta.ID, name)
}

// addressAllowed refuses a caller whose address is not on a secret's list.
//
// It applies to reads, writes and deletions alike. A restriction that only
// governed reading would let the same device it was written against overwrite
// or destroy the secret from anywhere - which is the opposite of what someone
// pinning a secret to an address expects, and deletion is the most damaging of
// the three.
func (s *Server) addressAllowed(w http.ResponseWriter, r *http.Request, tok store.ServiceToken, secretID, name string) bool {
	allowed, err := s.vault.DB().SecretAllowsAddress(r.Context(), secretID, s.clientIP(r))
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if !allowed {
		s.auditToken(r, tok, "access.denied", name, "adresse non autorisée pour ce secret")
		writeError(w, http.StatusForbidden, codeForbidden,
			"ce secret n'est pas accessible depuis cette adresse")
		return false
	}
	return true
}

// scopedName reads the name parameter and checks the token may act on this
// vault with the given intent.
func (s *Server) scopedName(w http.ResponseWriter, r *http.Request, tok store.ServiceToken, write bool) (string, bool) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest,
			"indique le secret avec ?name=...")
		return "", false
	}
	if len(name) > store.MaxSecretNameLength {
		writeError(w, http.StatusBadRequest, codeBadRequest, "ce nom est trop long")
		return "", false
	}

	if !tok.Allows(tok.ProjectID, tok.Env, write) {
		s.auditToken(r, tok, "access.denied", name, deniedReason(write))
		writeError(w, http.StatusForbidden, codeForbidden, "this token cannot reach that secret")
		return "", false
	}
	// A token narrowed to a few entries reaches those and nothing else, even
	// inside the vault it was issued for.
	if !tok.AllowsSecret(name) {
		s.auditToken(r, tok, "access.denied", name, "secret hors de la portée du token")
		writeError(w, http.StatusForbidden, codeForbidden, "this token cannot reach that secret")
		return "", false
	}
	return name, true
}

func deniedReason(write bool) string {
	if write {
		return "token en lecture seule"
	}
	return "hors de la portée du token"
}

// fail turns an internal error into a response, mapping the few cases a client
// is entitled to distinguish and hiding the rest.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, "no such secret")
	case errors.Is(err, vault.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, codeSealed,
			"the server is sealed and cannot serve secrets")
	default:
		// The detail goes to the operator's log, never to the client: it can
		// name vaults, names and internal state.
		logInternal(r, err)
		writeError(w, http.StatusInternalServerError, codeInternal, "internal error")
	}
}

// logInternal records an error that is deliberately not shown to the client.
func logInternal(r *http.Request, err error) {
	log.Printf("api: %s %s: %v", r.Method, r.URL.Path, err)
}
