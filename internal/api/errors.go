package api

import (
	"encoding/json"
	"log"
	"net/http"
)

// errorBody is the shape of every failure response.
//
// Code is a stable machine-readable string; Message is for whoever is reading
// a log at three in the morning. Neither ever carries internal detail: a
// device that fails to authenticate learns that it failed, not why.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes returned by the API.
const (
	codeUnauthorized = "unauthorized"
	codeForbidden    = "forbidden"
	codeNotFound     = "not_found"
	codeBadRequest   = "bad_request"
	codeSealed       = "sealed"
	codeInternal     = "internal"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Secrets must never be cached, by a browser or by anything in between.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already on the wire; all that is left is a note
		// for the operator.
		log.Printf("api: writing response body: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Code: code, Message: message})
}

// writeText sends a rendered export, which is not JSON.
func writeText(w http.ResponseWriter, status int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		log.Printf("api: writing response body: %v", err)
	}
}

// securityHeaders sets the handful that matter for an API serving secrets.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// Nothing here is meant to be framed or embedded.
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// recoverPanics keeps one broken request from taking the whole server down.
//
// A home server has nobody watching it and no orchestrator to restart it; a
// panic that killed the process would leave the house without its secrets
// until somebody noticed.
func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("api: panic serving %s %s: %v", r.Method, r.URL.Path, p)
				writeError(w, http.StatusInternalServerError, codeInternal, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
