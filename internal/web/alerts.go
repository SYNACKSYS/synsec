package web

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"synsec/internal/alert"
	"synsec/internal/store"
)

// Configuring the alerts.
//
// The page belongs to the account the server was set up with, like the
// journal: what it announces spans every vault, and the address it announces
// to is a place secrets' names end up. Handing that to anybody carrying the
// administrator flag would undo the vault separation by another route.

// alertTimeout bounds a test send, so a wrong address does not hold a browser
// request open for as long as the network feels like.
const alertTimeout = 15 * time.Second

func (s *Server) showAlerts(w http.ResponseWriter, r *http.Request) {
	s.renderAlerts(w, r, http.StatusOK, r.URL.Query().Get("info"), r.URL.Query().Get("erreur"))
}

func (s *Server) renderAlerts(w http.ResponseWriter, r *http.Request, code int, notice, errText string) {
	user := userFrom(r)

	url, err := s.vault.SealedSetting(r.Context(), alert.SettingURL, "")
	if err != nil {
		// A sealed server cannot read it. Saying so beats an error page: the
		// setting is fine, it is the key that is away.
		url = ""
	}
	secret, err := s.vault.SealedSetting(r.Context(), alert.SettingSecret, "")
	if err != nil {
		secret = ""
	}
	enabled, err := s.vault.DB().ServerSetting(r.Context(), alert.SettingEnabled, "")
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	level, err := s.vault.DB().ServerSetting(r.Context(), alert.SettingLevel, alert.SeverityWarning.String())
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	data := pageData{
		Title:        "Alertes",
		Nav:          "alertes",
		User:         &user,
		CSRF:         csrfFrom(r),
		Sealed:       s.vault.Sealed(),
		Notice:       notice,
		Error:        errText,
		AlertURL:     url,
		AlertSecret:  secret,
		AlertEnabled: enabled == "1",
		AlertLevel:   level,
		AlertLevels:  alertLevels(level),
		AlertSample:  sampleEvent(),
	}
	if s.alerts != nil {
		st := s.alerts.Status()
		data.AlertStatus = &alertStatusRow{
			LastAttempt: st.LastAttempt,
			LastSuccess: st.LastSuccess,
			LastError:   st.LastError,
			Sent:        st.Sent,
			Failed:      st.Failed,
			Capped:      st.Capped,
		}
	}
	s.render(w, r, "alerts.html", code, data)
}

// alertLevels are the three choices, with the one in force marked.
func alertLevels(current string) []alertLevelRow {
	rows := []alertLevelRow{
		{Value: "critique", Label: "Critique seulement",
			Hint: "Refus d'accès, suppressions, serveur rouvert avec le code de récupération."},
		{Value: "avertissement", Label: "Critique et avertissements",
			Hint: "Ajoute les accès donnés, les appareils créés, les comptes et les règles du serveur."},
		{Value: "info", Label: "Tout",
			Hint: "Ajoute les mots de passe ratés, les imports, les adresses jamais vues."},
	}
	for i := range rows {
		rows[i].Chosen = rows[i].Value == current
	}
	return rows
}

func (s *Server) saveAlerts(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres/alertes"

	url := strings.TrimSpace(r.PostFormValue("url"))
	want := r.PostFormValue("enabled") != ""
	level := strings.TrimSpace(r.PostFormValue("level"))
	if _, ok := alert.ParseSeverity(level); !ok {
		level = alert.SeverityWarning.String()
	}

	// Switching it on without anywhere to send is the mistake that produces a
	// server which believes it is watched and is not.
	if want && url == "" {
		s.redirectWithError(w, r, back, "Indique l'adresse du webhook avant d'activer les alertes.")
		return
	}
	if url != "" {
		if err := alert.ValidateURL(url); err != nil {
			s.redirectWithError(w, r, back, capitalise(err.Error())+".")
			return
		}
	}

	if _, err := alert.SaveWebhook(r.Context(), s.vault, url); err != nil {
		s.fail(w, r, user, err)
		return
	}
	stored := ""
	if want {
		stored = "1"
	}
	if err := s.vault.DB().SetServerSetting(r.Context(), alert.SettingEnabled, stored); err != nil {
		s.fail(w, r, user, err)
		return
	}
	if err := s.vault.DB().SetServerSetting(r.Context(), alert.SettingLevel, level); err != nil {
		s.fail(w, r, user, err)
		return
	}

	detail := "alertes désactivées"
	if want {
		detail = "alertes actives, niveau " + level
	}
	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "server.policy", Detail: detail,
	})

	if want {
		s.redirectWithNotice(w, r, back,
			"Alertes enregistrées. Envoie un test pour vérifier que le destinataire les reçoit.")
		return
	}
	s.redirectWithNotice(w, r, back, "Alertes désactivées. Le journal, lui, continue de tout enregistrer.")
}

// testAlerts sends one message on demand.
//
// The whole point is to find out that the address is wrong today, while
// somebody is looking at the form, rather than on the night it matters.
func (s *Server) testAlerts(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres/alertes"

	if s.alerts == nil {
		s.redirectWithError(w, r, back, "Les alertes ne tournent pas dans ce processus.")
		return
	}

	hostname, _ := os.Hostname()
	cfg, err := alert.LoadConfig(r.Context(), s.vault, hostname)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	// A test must work before the switch is flipped, otherwise nobody can
	// check an address without first arming a system they have not checked.
	if cfg.Webhook.URL == "" {
		url, err := s.vault.SealedSetting(r.Context(), alert.SettingURL, "")
		if err != nil || url == "" {
			s.redirectWithError(w, r, back, "Enregistre d'abord une adresse.")
			return
		}
		secret, _ := s.vault.SealedSetting(r.Context(), alert.SettingSecret, "")
		cfg.Webhook.URL, cfg.Webhook.Secret, cfg.Webhook.Server = url, secret, hostname
	}

	ctx, cancel := context.WithTimeout(r.Context(), alertTimeout)
	defer cancel()
	if err := s.alerts.Test(ctx, cfg); err != nil {
		s.redirectWithError(w, r, back, "Le message n'est pas parti : "+err.Error())
		return
	}
	s.redirectWithNotice(w, r, back, "Message de test envoyé. Regarde ce qui l'a reçu.")
}

// sampleEvent is what a message looks like, shown on the page so somebody
// writing the receiving end has the shape in front of them.
func sampleEvent() string {
	return `{
  "server": "synsec",
  "sent_at": "2026-07-30T03:14:07Z",
  "events": [
    {
      "kind": "access.denied.address",
      "severity": "critique",
      "at": "2026-07-30T03:14:02Z",
      "summary": "Secret refusé à un appareil : adresse non autorisée",
      "actor": "domotique",
      "actor_kind": "token",
      "vault": "Maison",
      "target": "mot_de_passe_mqtt",
      "ip": "203.0.113.7",
      "detail": "adresse non autorisée pour ce secret",
      "count": 34
    }
  ]
}`
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
