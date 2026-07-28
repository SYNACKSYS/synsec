package web

import (
	"net/http"
	"strings"

	"synsec/internal/importer"
	"synsec/internal/store"
)

// maxImportBytes caps an uploaded file.
//
// A secrets.yaml holding a household's passwords is a few kilobytes. A
// megabyte means the wrong file was chosen, and refusing it early is kinder
// than parsing it.
const maxImportBytes = 1 << 20

// showImport renders the upload form.
func (s *Server) showImport(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, role, ok := s.requireVault(w, r, store.RoleWriter)
	if !ok {
		return
	}

	s.render(w, r, "import.html", http.StatusOK, pageData{
		Title:    "Importer dans " + vault.Name,
		Nav:      "coffres",
		User:     &user,
		CSRF:     csrfFrom(r),
		Sealed:   s.vault.Sealed(),
		Vault:    &vaultRow{ID: vault.ID, Name: vault.Name},
		Role:     role,
		CanWrite: true,
		Error:    r.URL.Query().Get("erreur"),
	})
}

// runImport reads the uploaded file and creates the entries.
//
// One step rather than a preview followed by a confirmation: a browser does
// not keep a chosen file across a round trip, so the second step would mean
// picking it again. What makes that safe is that nothing is destroyed - an
// identifier already taken is left alone unless the box is ticked - and the
// report afterwards says exactly what happened to each line.
func (s *Server) runImport(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, role, ok := s.requireVault(w, r, store.RoleWriter)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/import"

	// The body was already parsed and size-capped while the CSRF token was
	// checked, so the form is decoded by the time this runs.
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, header, err := r.FormFile("fichier")
	if err != nil {
		s.redirectWithError(w, r, back, "Choisis un fichier à importer.")
		return
	}
	defer file.Close()

	if header.Size > maxImportBytes {
		s.redirectWithError(w, r, back,
			"Ce fichier dépasse un mégaoctet : ce n'est pas un fichier de secrets.")
		return
	}

	// The format is read from the name as sent. Deciding it from the shortened
	// one below would drop the extension of a long name and silently parse a
	// secrets.yaml as an env file.
	format := strings.TrimSpace(r.FormValue("format"))
	if format == "" {
		format = importer.DetectFormat(header.Filename)
	}

	// The filename comes from the client. It is shown back and written to the
	// log, so it is bounded rather than trusted to be reasonable.
	filename := truncate(header.Filename, 120)

	entries, err := importer.Parse(file, format)
	if err != nil {
		// The parser names the line and says what is wrong with it; passing
		// that through verbatim is more use than any wording of mine.
		s.redirectWithError(w, r, back, filename+" : "+err.Error())
		return
	}
	if len(entries) == 0 {
		s.redirectWithError(w, r, back, filename+" ne contient aucune entrée.")
		return
	}

	taken, err := s.takenNames(r, vault.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	plan, err := importer.BuildPlan(entries, taken, r.FormValue("remplacer") != "", store.Slugify)
	if err != nil {
		s.redirectWithError(w, r, back, err.Error())
		return
	}

	written := 0
	for _, item := range plan.Items {
		if item.Skip {
			continue
		}
		loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: item.Name}
		if _, err := s.vault.PutSecret(r.Context(), loc, []byte(item.Entry.Value), item.Entry.Key, user.Username); err != nil {
			s.fail(w, r, user, err)
			return
		}
		written++
	}

	if written > 0 {
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
			Action: "secret.import", Target: vault.Name,
			Detail: filename + " : " + plural(written, "1 secret", itoa(written)+" secrets"),
		})
	}

	s.render(w, r, "import_done.html", http.StatusOK, pageData{
		Title:    "Import dans " + vault.Name,
		Nav:      "coffres",
		User:     &user,
		CSRF:     csrfFrom(r),
		Sealed:   s.vault.Sealed(),
		Vault:    &vaultRow{ID: vault.ID, Name: vault.Name},
		Imported: toImportRows(plan),
		Written:  written,
		Skipped:  plan.Skipped(),
		Filename: filename,
		Role:     role,
		CanWrite: true,
	})
}

// toImportRows turns a plan into what the report page shows. Values are left
// out: the point of the exercise is to stop them being readable.
func toImportRows(plan importer.Plan) []importRow {
	rows := make([]importRow, 0, len(plan.Items))
	for _, item := range plan.Items {
		rows = append(rows, importRow{
			Key:    item.Entry.Key,
			Name:   item.Name,
			Reason: item.Reason,
			Skip:   item.Skip,
		})
	}
	return rows
}

// itoa avoids importing strconv for a count that never exceeds a few hundred.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for n > 0 && i > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
