package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Ce que la règle « second facteur obligatoire » accepte exactement.
//
// L'affirmation à vérifier : une application d'authentification suffit, une
// clé de sécurité suffit, et les deux ensemble marchent aussi. Chacun de ces
// trois états doit lever la contrainte et permettre de se reconnecter
// ensuite - ce second point compte autant, parce qu'une règle qui laisse
// s'enrôler puis refuse la connexion suivante enferme le compte dehors.

// password signs in as far as the password takes it and hands back the page,
// which is where the choice of proofs is drawn.
func (h *harness) password(t *testing.T, username string) *http.Response {
	t.Helper()
	h.newJar(t)

	resp := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {username},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("l'étape du mot de passe répond %d", resp.StatusCode)
	}
	return resp
}

// answerWithCode finishes the sign-in with a one-time code. Une réponse
// valide redirige - 303 - vers la page d'accueil ; c'est le succès, pas 200.
func (h *harness) answerWithCode(t *testing.T, secret string) *http.Response {
	t.Helper()
	return h.post(t, "/login/code", url.Values{
		"login_csrf": {h.loginToken(t)},
		"code":       {codeFor(t, secret, time.Now())},
	})
}

func TestAnApplicationAloneSatisfiesThePolicy(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(pin(true)))
	h.signIn(t)

	secret, _ := h.enableTwoFactor(t)

	if code := h.get(t, "/").StatusCode; code != http.StatusOK {
		t.Fatalf("l'accueil répond %d après l'enrôlement d'une application", code)
	}

	h.password(t, "cyril")
	if resp := h.answerWithCode(t, secret); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("la reconnexion par code répond %d, attendu 303", resp.StatusCode)
	}
	if code := h.get(t, "/").StatusCode; code != http.StatusOK {
		t.Fatalf("pas de session après le code (%d)", code)
	}
}

func TestASecurityKeyAloneSatisfiesThePolicy(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(pin(true)))
	h.signIn(t)

	key := newFakeKey(t, "la-cle-seule")
	h.registerKey(t, key, "YubiKey")

	if code := h.get(t, "/").StatusCode; code != http.StatusOK {
		t.Fatalf("l'accueil répond %d après l'enrôlement d'une clé", code)
	}

	// Aucune application n'est enregistrée : la clé seule doit ramener une
	// session.
	h.password(t, "cyril")
	if resp := h.answerWithKey(t, key, 1); resp.StatusCode != http.StatusOK {
		t.Fatalf("la reconnexion par clé répond %d : %s", resp.StatusCode, body(t, resp))
	}
	if code := h.get(t, "/").StatusCode; code != http.StatusOK {
		t.Fatalf("pas de session après la clé (%d)", code)
	}
}

// Les deux ensemble : chacune des deux preuves ouvre la session.
func TestBothFactorsTogetherAreAccepted(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(pin(true)))
	h.signIn(t)

	secret, _ := h.enableTwoFactor(t)
	key := newFakeKey(t, "la-cle-en-plus")
	h.registerKey(t, key, "YubiKey")

	if code := h.get(t, "/").StatusCode; code != http.StatusOK {
		t.Fatalf("l'accueil répond %d avec les deux facteurs", code)
	}

	h.password(t, "cyril")
	if resp := h.answerWithKey(t, key, 1); resp.StatusCode != http.StatusOK {
		t.Fatalf("la clé est refusée alors qu'une application existe aussi (%d)", resp.StatusCode)
	}
	if code := h.get(t, "/").StatusCode; code != http.StatusOK {
		t.Fatalf("pas de session après la clé (%d)", code)
	}

	h.password(t, "cyril")
	if resp := h.answerWithCode(t, secret); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("le code est refusé alors qu'une clé existe aussi (%d)", resp.StatusCode)
	}
	if code := h.get(t, "/").StatusCode; code != http.StatusOK {
		t.Fatalf("pas de session après le code (%d)", code)
	}
}

// La page de vérification ne propose que ce que le compte porte. Offrir une
// clé à qui n'en a pas est une impasse ; offrir un code à qui n'a pas
// d'application aussi.
func TestTheVerificationPageOffersOnlyWhatTheAccountHas(t *testing.T) {
	t.Run("application seule", func(t *testing.T) {
		h := newHarness(t, RequireSecondFactor(pin(true)))
		h.signIn(t)
		h.enableTwoFactor(t)

		page := body(t, h.password(t, "cyril"))
		if !strings.Contains(page, "Code de ton application") {
			t.Error("le champ du code n'est pas proposé")
		}
		if strings.Contains(page, `data-webauthn="login"`) {
			t.Error("une clé est proposée à un compte qui n'en a pas")
		}
	})

	t.Run("clé seule", func(t *testing.T) {
		h := newHarness(t, RequireSecondFactor(pin(true)))
		h.signIn(t)
		h.registerKey(t, newFakeKey(t, "k"), "clé")

		page := body(t, h.password(t, "cyril"))
		if !strings.Contains(page, `data-webauthn="login"`) {
			t.Error("la clé n'est pas proposée")
		}
		if strings.Contains(page, "Code de ton application") {
			t.Error("un code d'application est proposé à un compte qui n'en a pas")
		}
		// Le repli reste offert : qui a perdu sa clé n'a plus que ses codes
		// de secours, et c'est sur cette page qu'il doit les trouver.
		if !strings.Contains(page, "Code de secours") {
			t.Error("aucun repli pour une clé perdue")
		}
	})

	t.Run("les deux", func(t *testing.T) {
		h := newHarness(t, RequireSecondFactor(pin(true)))
		h.signIn(t)
		h.enableTwoFactor(t)
		h.registerKey(t, newFakeKey(t, "k"), "clé")

		page := body(t, h.password(t, "cyril"))
		if !strings.Contains(page, "Code de ton application") || !strings.Contains(page, `data-webauthn="login"`) {
			t.Error("la page ne propose pas les deux preuves")
		}
	})
}
