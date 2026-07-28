package web

import (
	"net/http"

	"synsec/internal/store"
)

// The server's own rules, as opposed to each person's preferences.
//
// Only what can change while the server runs lives here. An address to listen
// on or a certificate to load is read once at start-up, so offering it in a
// browser would promise a change that nothing applies - and a page that lies
// about what it did is worse than one that does not offer the choice.

// settingRequire2FA is the stored form of the second-factor policy: "1" or
// absent. Named here because the server reads it at start-up and the page
// writes it.
const settingRequire2FA = "require_second_factor"

func (s *Server) showServerSettings(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	s.render(w, r, "serversettings.html", http.StatusOK, pageData{
		Title:       "Sécurité du serveur",
		Nav:         "serveur",
		User:        &user,
		CSRF:        csrfFrom(r),
		Sealed:      s.vault.Sealed(),
		SessionIdle: humanDuration(s.sessionIdle),
		Notice:      r.URL.Query().Get("info"),
		Error:       r.URL.Query().Get("erreur"),
	})
}

func (s *Server) saveServerSettings(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres/serveur"

	// A pinned policy is not editable here, and the page does not offer it.
	// Refused rather than ignored: a form that appears to work and changes
	// nothing is how somebody concludes the server is broken.
	if s.requirePin != nil {
		s.redirectWithError(w, r, back,
			"Cette règle est fixée au démarrage du serveur. Change l'option -require-2fa et redémarre.")
		return
	}

	want := r.PostFormValue("require_2fa") != ""

	// Turning it on locks every account without a second factor out of
	// everything but the enrolment pages - including this one. Somebody who
	// does it from an account that has no factor, on a server reached by its
	// address rather than by a name, would have no key to register and no way
	// back short of restarting the server with the option pinned off.
	if want {
		has, err := s.vault.DB().HasSecondFactor(r.Context(), user.ID)
		if err != nil {
			s.fail(w, r, user, err)
			return
		}
		if !has {
			s.redirectWithError(w, r, back,
				"Enregistre d'abord ton propre second facteur : cette règle t'enfermerait aussitôt hors de tes coffres.")
			return
		}
	}

	stored := ""
	if want {
		stored = "1"
	}
	if err := s.vault.DB().SetServerSetting(r.Context(), settingRequire2FA, stored); err != nil {
		s.fail(w, r, user, err)
		return
	}
	s.requireStored.Store(want)

	detail := "second facteur non obligatoire"
	if want {
		detail = "second facteur obligatoire"
	}
	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "server.policy", Detail: detail,
	})

	if want {
		s.redirectWithNotice(w, r, back,
			"Second facteur désormais obligatoire. Les comptes qui n'en ont pas ne verront que les pages d'enrôlement.")
		return
	}
	s.redirectWithNotice(w, r, back,
		"Second facteur redevenu facultatif. Ceux qui en ont un le gardent.")
}
