// Package alert turns what the journal records into notifications.
//
// Everything SYNSEC does already writes a line: a read, a refusal, a grant, a
// deletion. So nothing here is wired into the handlers - a single reader
// follows the log and decides what deserves saying out loud. That is what
// makes the browser, the API and the command line all alert alike, including
// the command line, which runs in a different process entirely and could not
// have called a notifier even if we had asked it to.
//
// It also means an alert can never claim something that is not in the journal,
// and the journal can never quietly hold something an alert would have shown.
package alert

import (
	"strings"

	"synsec/internal/store"
)

// Severity is how loudly an event asks for attention.
//
// Three levels rather than a switch per event: the person configuring this
// wants to say "wake me for the serious things", not to tick forty boxes and
// discover a year later which one they left off.
type Severity int

const (
	// SeverityInfo: worth knowing, not worth interrupting anyone.
	SeverityInfo Severity = iota
	// SeverityWarning: somebody now has access they did not have before, or
	// the rules of the server changed.
	SeverityWarning
	// SeverityCritical: an access was refused, something was destroyed, or
	// the root key was opened with the recovery code.
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critique"
	case SeverityWarning:
		return "avertissement"
	default:
		return "info"
	}
}

// ParseSeverity reads the stored form of a level.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "info", "tout":
		return SeverityInfo, true
	case "avertissement", "warning":
		return SeverityWarning, true
	case "critique", "critical":
		return SeverityCritical, true
	}
	return SeverityCritical, false
}

// Kind names what happened, in a form a receiving script can switch on.
//
// Stable identifiers in English, like the actions in the journal they come
// from: a rule written in Home Assistant should not break because a label was
// reworded in the interface.
type Kind string

const (
	KindAccessDeniedAddress Kind = "access.denied.address"
	KindAccessDeniedScope   Kind = "access.denied.scope"
	KindAccessDenied        Kind = "access.denied"
	KindAuthFailed          Kind = "auth.failed"
	KindAuthLocked          Kind = "auth.locked"
	KindRecoveryUsed        Kind = "vault.recovered"
	KindVaultDeleted        Kind = "vault.deleted"
	KindSecretDeleted       Kind = "secret.deleted"
	KindAccessGranted       Kind = "access.granted"
	KindTokenCreated        Kind = "token.created"
	KindTokenScope          Kind = "token.scope"
	KindAccountChanged      Kind = "account.changed"
	KindPolicyChanged       Kind = "server.policy"
	KindNewAddress          Kind = "address.new"
)

// rule is what one kind of journal line becomes.
type rule struct {
	kind    Kind
	sev     Severity
	summary string
}

// rules maps a journal action to what it means for somebody watching.
//
// Absent means silent. Reads are absent deliberately: a household server does
// a few thousand a week, and a notification that arrives that often is one
// nobody reads. The secret's own page answers "who opened this", which is the
// question reads are actually asked for.
var rules = map[string]rule{
	// The root key was opened by somebody holding the printed code, and
	// re-sealed to whatever machine they were standing at. Nothing on this
	// server is more serious.
	"vault.recovered": {KindRecoveryUsed, SeverityCritical, "Serveur rouvert avec le code de récupération"},
	"auth.throttled":  {KindAuthLocked, SeverityCritical, "Trop de mots de passe ratés : adresse bloquée"},
	"vault.delete":    {KindVaultDeleted, SeverityCritical, "Coffre supprimé"},
	"secret.delete":   {KindSecretDeleted, SeverityCritical, "Secret supprimé"},

	// Somebody can now reach something they could not reach before. None of
	// these is alarming on its own; all of them are worth seeing the day they
	// happen rather than the day something goes wrong.
	"vault.grant":      {KindAccessGranted, SeverityWarning, "Accès donné à un coffre"},
	"vault.share":      {KindAccessGranted, SeverityWarning, "Accès donné à un coffre"},
	"secret.share":     {KindAccessGranted, SeverityWarning, "Secret partagé"},
	"share.grant":      {KindAccessGranted, SeverityWarning, "Secret partagé"},
	"token.create":     {KindTokenCreated, SeverityWarning, "Nouvel appareil connecté"},
	"token.scope":      {KindTokenScope, SeverityWarning, "Portée d'un appareil modifiée"},
	"audit.grant":      {KindAccessGranted, SeverityWarning, "Journal ouvert à un compte"},
	"user.create":      {KindAccountChanged, SeverityWarning, "Compte créé"},
	"user.delete":      {KindAccountChanged, SeverityWarning, "Compte supprimé"},
	"user.password":    {KindAccountChanged, SeverityWarning, "Mot de passe réinitialisé par un administrateur"},
	"auth.recovery":    {KindAccountChanged, SeverityWarning, "Code de secours utilisé à la place du second facteur"},
	"auth.2fa.disable": {KindAccountChanged, SeverityWarning, "Vérification en deux étapes désactivée"},
	"auth.key.remove":  {KindAccountChanged, SeverityWarning, "Clé de sécurité retirée"},
	"server.policy":    {KindPolicyChanged, SeverityWarning, "Règle du serveur modifiée"},
	"secret.pin":       {KindPolicyChanged, SeverityWarning, "Restriction d'adresse ajoutée sur un secret"},
	"secret.unpin":     {KindPolicyChanged, SeverityWarning, "Restriction d'adresse retirée d'un secret"},

	"auth.failed":   {KindAuthFailed, SeverityInfo, "Mot de passe refusé"},
	"secret.import": {KindAccountChanged, SeverityInfo, "Secrets importés"},
	"vault.rotate":  {KindPolicyChanged, SeverityInfo, "Clé d'un coffre renouvelée"},
	"secret.revert": {KindPolicyChanged, SeverityInfo, "Retour à une version précédente"},
}

// classify turns one journal line into an event, or reports that it says
// nothing worth sending.
//
// Refusals are split by cause, because the causes are not the same news. An
// address the owner pinned a secret to, refused, means a device is talking
// from somewhere it never should - that is the alarm. A token reaching outside
// its scope is usually a misconfigured integration, worth knowing about today
// rather than at three in the morning.
func classify(e store.AuditEntry) (rule, bool) {
	if e.Action == "access.denied" {
		switch {
		case strings.Contains(e.Detail, "adresse"):
			return rule{KindAccessDeniedAddress, SeverityCritical,
				"Secret refusé à un appareil : adresse non autorisée"}, true
		case strings.Contains(e.Detail, "portée"):
			return rule{KindAccessDeniedScope, SeverityWarning,
				"Appareil hors de sa portée"}, true
		default:
			return rule{KindAccessDenied, SeverityCritical, "Accès refusé"}, true
		}
	}

	r, ok := rules[e.Action]
	return r, ok
}
