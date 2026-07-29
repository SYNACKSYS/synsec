package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"synsec/internal/store"
)

// maxSecretBytes caps a value submitted from a form. A secret is a password or
// a key, not a payload.
const maxSecretBytes = 64 << 10

// showNewVault renders the creation form on its own page, rather than parking
// it permanently under the vault list where it competes with the content.
func (s *Server) showNewVault(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	s.render(w, r, "vault_new.html", http.StatusOK, pageData{
		Title:  "Nouveau coffre",
		Nav:    "coffres",
		User:   &user,
		CSRF:   csrfFrom(r),
		Sealed: s.vault.Sealed(),
		Error:  r.URL.Query().Get("erreur"),
	})
}

// createVault adds a vault and makes its creator the manager.
func (s *Server) createVault(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.redirectWithError(w, r, "/coffres/nouveau", "Donne un nom à ton coffre.")
		return
	}

	vault, err := s.vault.CreateVault(r.Context(), name, strings.TrimSpace(r.PostFormValue("description")), user.ID)
	if err != nil {
		if store.IsConstraintViolation(err) {
			s.redirectWithError(w, r, "/coffres/nouveau", "Un coffre porte déjà ce nom.")
			return
		}
		// A refused name is the person's to fix, not an internal failure.
		if errors.Is(err, store.ErrVaultName) {
			s.redirectWithError(w, r, "/coffres/nouveau", vaultNameProblem(err))
			return
		}
		s.fail(w, r, user, err)
		return
	}

	// Without this the creator could not reach what they just made, unless
	// they happen to be a server administrator.
	if err := s.vault.DB().SetVaultMember(r.Context(), vault.ID, user.ID, store.RoleManager, user.Username); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "vault.create", Target: vault.Name,
	})
	http.Redirect(w, r, "/coffres/"+vault.ID, http.StatusSeeOther)
}

// showVault lists the secrets of one vault.
//
// No value is decrypted here: the list shows names and versions only, so
// opening a vault costs nothing in cryptography and leaves nothing on screen
// for whoever walks past.
func (s *Server) showVault(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, role, ok := s.requireVault(w, r, store.RoleReader)
	if !ok {
		return
	}

	secrets, err := s.vault.DB().ListSecrets(r.Context(), vault.ID, store.DefaultEnvironment)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	rows := make([]secretRow, 0, len(secrets))
	for _, sec := range secrets {
		rows = append(rows, secretRow{
			Name:      sec.Name,
			Label:     sec.Label,
			Version:   sec.CurrentVersion,
			UpdatedAt: sec.UpdatedAt,
		})
	}

	s.render(w, r, "vault.html", http.StatusOK, pageData{
		Title:     vault.Name,
		Nav:       "coffres",
		User:      &user,
		CSRF:      csrfFrom(r),
		Sealed:    s.vault.Sealed(),
		Vault:     &vaultRow{ID: vault.ID, Name: vault.Name, Description: vault.Description},
		Secrets:   rows,
		Role:      role,
		CanWrite:  role.AtLeast(store.RoleWriter),
		CanManage: role.AtLeast(store.RoleManager),
		CanDelete: ownsVault(user, vault),
		Notice:    r.URL.Query().Get("info"),
		Error:     r.URL.Query().Get("erreur"),
	})
}

// ownsVault reports whether someone may destroy a vault.
//
// The owner, and nobody else. Managing a vault means deciding who gets in;
// destroying it takes everyone's secrets with it, including those of people
// the owner shared it with, and that is not a decision to delegate along with
// the ability to add a member.
//
// A vault whose owner's account was deleted has none, and would otherwise be
// undeletable, so a manager may finish the job.
func ownsVault(user store.User, vault store.Project) bool {
	if vault.OwnerID == "" {
		return true // caller has already been checked for the manager role
	}
	return vault.OwnerID == user.ID
}

// deleteVault destroys a vault and everything in it.
func (s *Server) deleteVault(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID
	if !ownsVault(user, vault) {
		s.redirectWithError(w, r, back,
			"Seul le propriétaire du coffre peut le supprimer.")
		return
	}

	// The name has to be typed out. A confirmation dialog is answered by
	// reflex; writing "Maison" is not something anyone does by accident, and
	// this is the one action in SYNSEC that no backup taken afterwards can
	// undo.
	// The identifier confirms as well as the name. A vault whose name cannot be
	// retyped - one created by something that fills every field with a payload
	// - would otherwise be undeletable by its own owner.
	if c := strings.TrimSpace(r.PostFormValue("confirm")); c != vault.Name && c != vault.ID {
		s.redirectWithError(w, r, back,
			"Pour supprimer ce coffre, recopie son nom exactement : "+vault.Name+
				" - ou son identifiant : "+vault.ID)
		return
	}

	secrets, err := s.vault.DB().ListSecrets(r.Context(), vault.ID, store.DefaultEnvironment)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	if err := s.vault.DB().DeleteProject(r.Context(), vault.ID); err != nil {
		s.fail(w, r, user, err)
		return
	}

	// Written after the fact and with a count, because the rows it refers to
	// no longer exist: the log is the only thing left that says what was there.
	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "vault.delete", Target: vault.Name,
		Detail: strconv.Itoa(len(secrets)) + " " + plural(len(secrets), "secret", "secrets"),
	})
	s.redirectWithNotice(w, r, "/",
		"Coffre « "+vault.Name+" » supprimé, avec ses secrets et ses appareils.")
}

func plural(n int, one, many string) string {
	if n <= 1 {
		return one
	}
	return many
}

// showSecret renders the form for one secret, or an empty one for a new secret.
//
// Opening the form decrypts the value so it can be edited, and that read is
// audited like any other. An interface that let someone read a secret without
// leaving a trace would undo the point of the log.
func (s *Server) showSecret(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	name := strings.TrimSpace(r.URL.Query().Get("name"))

	// A blank name means "create", which is a right over the vault rather than
	// over any particular secret.
	if name == "" {
		vault, role, ok := s.requireVault(w, r, store.RoleWriter)
		if !ok {
			return
		}
		s.render(w, r, "secret.html", http.StatusOK, pageData{
			Title:       "Nouveau secret",
			Nav:         "coffres",
			User:        &user,
			CSRF:        csrfFrom(r),
			Sealed:      s.vault.Sealed(),
			Vault:       &vaultRow{ID: vault.ID, Name: vault.Name},
			Role:        role,
			CanWrite:    true,
			CanSeeVault: true, // creating requires write access to the vault
			Back:        "/coffres/" + vault.ID,
		})
		return
	}

	vault, secret, role, ok := s.requireSecret(w, r, name, store.RoleReader)
	if !ok {
		return
	}

	// The address restriction is deliberately not applied here. It exists to
	// pin a secret to the machine that consumes it, and it is checked where a
	// service token is used. Someone signed in has already proved who they are
	// with a password, and locks them out of their own secret the moment they
	// open the interface from the sofa instead of the server.
	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: secret.Name}
	value, err := s.vault.GetSecret(r.Context(), loc)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	// Someone who holds only a share on this secret cannot open the vault
	// around it, so neither the breadcrumb nor the cancel button may lead
	// there - they would land on a page telling them it does not exist.
	back, canSeeVault := s.backFromSecret(r, user, vault.ID)

	// Only a manager sees, or sets, where this secret may be read from.
	var networks []networkRow
	if role.AtLeast(store.RoleManager) {
		if networks, err = s.networksOf(r, secret.ID); err != nil {
			s.fail(w, r, user, err)
			return
		}
	}

	// The history, metadata only. Listing it decrypts nothing: a page that
	// opened every past version to display a list would read far more than
	// the visitor asked for, and say so in the log.
	versions, err := s.versionsOf(r, secret)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.read", Target: secret.Name,
	})

	s.render(w, r, "secret.html", http.StatusOK, pageData{
		Title:  secret.Name,
		Nav:    "coffres",
		User:   &user,
		CSRF:   csrfFrom(r),
		Sealed: s.vault.Sealed(),
		Vault:  &vaultRow{ID: vault.ID, Name: vault.Name},
		Secret: &secretRow{
			Name: secret.Name, Label: secret.Label,
			Version: secret.CurrentVersion, UpdatedAt: secret.UpdatedAt,
		},
		Value:       string(value),
		Role:        role,
		CanWrite:    role.AtLeast(store.RoleWriter),
		CanManage:   role.AtLeast(store.RoleManager),
		CanSeeVault: canSeeVault,
		Networks:    networks,
		Versions:    versions,
		Back:        back,
	})
}

// versionsOf reads a secret's history for display.
func (s *Server) versionsOf(r *http.Request, secret store.Secret) ([]versionRow, error) {
	found, err := s.vault.DB().ListVersions(r.Context(), secret.ID)
	if err != nil {
		return nil, err
	}

	rows := make([]versionRow, 0, len(found))
	for _, v := range found {
		rows = append(rows, versionRow{
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy,
			Current:   v.Version == secret.CurrentVersion,
		})
	}
	return rows, nil
}

// revertSecret brings an old value back as a new version.
//
// The history is never rewritten: coming back to version 2 writes a version 5
// holding the same value. Someone reading the log afterwards sees that it
// happened, when, and by whose hand - which a silent rollback would hide.
func (s *Server) revertSecret(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	name := strings.TrimSpace(r.PostFormValue("name"))
	vault, secret, _, ok := s.requireSecret(w, r, name, store.RoleWriter)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/secret?name=" + urlEncode(secret.Name)

	version, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("version")), 10, 64)
	if err != nil {
		s.redirectWithError(w, r, back, "Version illisible.")
		return
	}
	if version == secret.CurrentVersion {
		s.redirectWithError(w, r, back, "C'est déjà la version en cours.")
		return
	}

	restored, err := s.vault.RevertSecret(r.Context(), secret.SecretLocation, version, user.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || strings.Contains(err.Error(), "n'a pas de version") {
			s.redirectWithError(w, r, back, "Cette version n'existe pas.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.revert", Target: secret.Name,
		Detail: "v" + strconv.FormatInt(version, 10) + " reprise en v" + strconv.FormatInt(restored.CurrentVersion, 10),
	})
	s.redirectWithNotice(w, r, back, "Valeur de la version "+strconv.FormatInt(version, 10)+
		" rétablie, enregistrée en version "+strconv.FormatInt(restored.CurrentVersion, 10)+".")
}

// takenNames lists the identifiers already used in a vault, so a derived slug
// can step aside rather than land on one.
func (s *Server) takenNames(r *http.Request, projectID string) (map[string]bool, error) {
	secrets, err := s.vault.DB().ListSecrets(r.Context(), projectID, store.DefaultEnvironment)
	if err != nil {
		return nil, err
	}

	taken := make(map[string]bool, len(secrets))
	for _, sec := range secrets {
		taken[sec.Name] = true
	}
	return taken, nil
}

// backFromSecret returns where to send someone leaving a secret, and whether
// the vault around it is theirs to open.
func (s *Server) backFromSecret(r *http.Request, user store.User, projectID string) (string, bool) {
	role, err := s.vaultRole(r.Context(), user, projectID)
	if err != nil {
		logError(r, err)
		return "/", false
	}
	if role.AtLeast(store.RoleReader) {
		return "/coffres/" + projectID, true
	}
	return "/", false
}

// saveSecret writes a new version of a secret.
//
// Which right is needed depends on whether the secret already exists: an
// individual share can authorise rewriting one secret, but creating a new one
// is a right over the vault. Access is settled before anything is said about
// the outcome, so a caller with none learns nothing - not even whether the
// name they submitted was well formed.
func (s *Server) saveSecret(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, err := s.vault.DB().Project(r.Context(), r.PathValue("id"))
	if err != nil {
		s.notFound(w, r)
		return
	}

	// The label is what its owner writes; the slug is derived from it unless
	// they typed one themselves. Only the slug is fixed for good, so the form
	// asks for the label first and the slug second.
	label := strings.TrimSpace(r.PostFormValue("label"))
	typed := strings.TrimSpace(r.PostFormValue("name"))
	editing := r.PostFormValue("editing") != ""

	submitted := typed
	if submitted == "" {
		submitted = store.Slugify(label)
	}

	name, nameErr := cleanSecretName(submitted)
	exists := false
	if nameErr == nil {
		loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: name}
		switch _, err := s.vault.DB().SecretMeta(r.Context(), loc); {
		case err == nil:
			exists = true
		case errors.Is(err, store.ErrNotFound):
		default:
			s.fail(w, r, user, err)
			return
		}
	}

	// Creating something whose identifier is already taken would write a new
	// version of somebody else's secret without a word - the person believes
	// they added an entry and has in fact replaced a value. A derived slug is
	// nudged aside; one that was typed is refused, because silently renaming
	// what someone wrote is its own kind of surprise.
	collision := exists && !editing
	if collision && typed == "" {
		taken, err := s.takenNames(r, vault.ID)
		if err != nil {
			s.fail(w, r, user, err)
			return
		}
		name = store.UniqueSlug(label, taken)
		exists, collision = false, false
	}

	var allowed bool
	if exists {
		_, _, _, allowed = s.requireSecret(w, r, name, store.RoleWriter)
	} else {
		_, _, allowed = s.requireVault(w, r, store.RoleWriter)
	}
	if !allowed {
		return // the gate has already answered
	}

	// Someone who was handed this one secret cannot open the vault, so they
	// must not be sent back into it once they have saved.
	back, _ := s.backFromSecret(r, user, vault.ID)

	if nameErr != nil {
		s.redirectWithError(w, r, back, nameErr.Error())
		return
	}
	if collision {
		s.redirectWithError(w, r, back,
			"Un secret porte déjà l'identifiant « "+name+" » dans ce coffre. "+
				"Choisis-en un autre, ou modifie le secret existant.")
		return
	}
	value := r.PostFormValue("value")
	if len(value) > maxSecretBytes {
		s.redirectWithError(w, r, back, "Cette valeur est trop longue.")
		return
	}

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: name}
	if _, err := s.vault.PutSecret(r.Context(), loc, []byte(value), label, user.Username); err != nil {
		if errors.Is(err, store.ErrLabel) {
			s.redirectWithError(w, r, back, labelProblem(err))
			return
		}
		s.fail(w, r, user, err)
		return
	}

	// Renaming what people read is free, so an edit applies the label even
	// when the secret already exists - unlike the slug, which is settled.
	if exists && label != "" {
		if err := s.vault.DB().SetSecretLabel(r.Context(), loc, label); err != nil {
			logError(r, err)
		}
	}

	// The value never reaches the log, only the fact that it changed.
	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.write", Target: name,
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// deleteSecret removes a secret and its history.
//
// Deliberately gated on the vault, not on the secret: an individual share
// never grants the right to destroy someone else's secret along with every
// version of it.
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleWriter)
	if !ok {
		return
	}

	name := strings.TrimSpace(r.PostFormValue("name"))
	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: name}

	if err := s.vault.DB().DeleteSecret(r.Context(), loc); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.redirectWithError(w, r, "/coffres/"+vault.ID, "Ce secret n'existe pas ou plus.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.delete", Target: name,
	})
	http.Redirect(w, r, "/coffres/"+vault.ID, http.StatusSeeOther)
}

// cleanSecretName normalises what someone typed into the form.
//
// The rule is the store's, so a secret written from the browser and one
// written by a device are held to the same thing. Nothing is silently
// transformed: what is refused is refused with a reason, because a name
// quietly rewritten is a name the owner will look for and not find.
func cleanSecretName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("Donne un nom à ton secret, par exemple mqtt_password.")
	}
	if err := store.ValidSecretName(name); err != nil {
		return "", errors.New("Un nom ne peut contenir que des lettres, des chiffres, " +
			"des tirets et des soulignés, et faire au plus 128 caractères.")
	}
	return name, nil
}

// redirectWithError sends the visitor back with a message.
//
// The message travels in the query string, which is why it must never carry
// anything sensitive: it lands in the browser's history.
// labelProblem turns a refused label into a sentence worth reading.
//
// The offending character is not repeated back: it came from the visitor, and
// the message travels in a query string that lands in browser history.
func labelProblem(err error) string {
	if strings.Contains(err.Error(), "dépasse") {
		return "C'est trop long : " + strconv.Itoa(store.MaxLabelLength) + " caractères au maximum."
	}
	return "Ce nom contient un caractère qui n'y a pas sa place. " +
		"Lettres, chiffres, espaces, et - _ . , ( ) [ ] { } @ $ & seulement."
}

// vaultNameProblem turns a refusal into a sentence worth reading.
//
// The offending character is not repeated back: it came from the visitor, and
// the message travels in a query string that lands in browser history.
func vaultNameProblem(err error) string {
	switch {
	case strings.Contains(err.Error(), "caractères au maximum"):
		return "Ce nom est trop long : " + strconv.Itoa(store.MaxVaultNameLength) + " caractères au maximum."
	case strings.Contains(err.Error(), "description"):
		return "La description est trop longue : " +
			strconv.Itoa(store.MaxVaultDescriptionLength) + " caractères au maximum."
	default:
		return "Ce nom contient un caractère qui n'y a pas sa place. " +
			"Lettres, chiffres, espaces, et - _ . , ( ) [ ] { } @ $ & seulement."
	}
}

func (s *Server) redirectWithError(w http.ResponseWriter, r *http.Request, to, message string) {
	http.Redirect(w, r, to+"?erreur="+urlEncode(message), http.StatusSeeOther)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, user store.User, err error) {
	logError(r, err)
	s.render(w, r, "message.html", http.StatusInternalServerError, pageData{
		Title: "Erreur", Nav: "coffres", User: &user, CSRF: csrfFrom(r),
		Error: "Quelque chose s'est mal passé. Le détail est dans le journal du serveur.",
	})
}
