package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"synsec/internal/store"
)

// upload posts a file the way a browser would.
func (h *harness) upload(t *testing.T, path, filename, body string, fields map[string]string) *http.Response {
	t.Helper()

	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	if err := form.WriteField("csrf", h.csrf(t)); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	for k, v := range fields {
		if err := form.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %s: %v", k, err)
		}
	}
	part, err := form.CreateFormFile("fichier", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	part.Write([]byte(body))
	form.Close()

	resp, err := h.client.Post(h.srv.URL+path, form.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

const secretsYAML = `# Ne jamais partager
mqtt_password: s3cr3t
wifi_ssid: "Livebox-1234"
`

func TestImportCreatesSecretsFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	resp := h.upload(t, "/coffres/"+vault.ID+"/import", "secrets.yaml", secretsYAML, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the import returned %d", resp.StatusCode)
	}

	page := body(t, resp)
	for _, want := range []string{"mqtt_password", "wifi_ssid", "nouveau"} {
		if !strings.Contains(page, want) {
			t.Errorf("the report does not mention %q", want)
		}
	}
	// The report must not hand the values back on screen.
	if strings.Contains(page, "s3cr3t") || strings.Contains(page, "Livebox-1234") {
		t.Fatal("a value was printed in the report")
	}

	secrets, err := h.manager.DB().ListSecrets(ctx, vault.ID, store.DefaultEnvironment)
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("%d secrets created, want 2", len(secrets))
	}

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	value, err := h.manager.GetSecret(ctx, loc)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != "s3cr3t" {
		t.Fatalf("the stored value is %q", value)
	}
}

// Importing the same file twice must not quietly write a second version of
// everything.
func TestSecondImportSkipsWhatExists(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	h.upload(t, "/coffres/"+vault.ID+"/import", "secrets.yaml", secretsYAML, nil)
	page := body(t, h.upload(t, "/coffres/"+vault.ID+"/import", "secrets.yaml", secretsYAML, nil))

	if !strings.Contains(page, "ignor") {
		t.Fatal("the second import does not report anything skipped")
	}

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	meta, err := h.manager.DB().SecretMeta(ctx, loc)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}
	if meta.CurrentVersion != 1 {
		t.Fatalf("the secret is at version %d: the second import overwrote it", meta.CurrentVersion)
	}
}

// Ticking the box is what makes overwriting deliberate.
func TestImportReplacesWhenAsked(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	h.upload(t, "/coffres/"+vault.ID+"/import", "secrets.yaml", secretsYAML, nil)
	h.upload(t, "/coffres/"+vault.ID+"/import", "secrets.yaml",
		"mqtt_password: nouveau\n", map[string]string{"remplacer": "1"})

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	value, err := h.manager.GetSecret(ctx, loc)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != "nouveau" {
		t.Fatalf("the value is %q, want the replacement", value)
	}

	// Replacing writes a version; it does not erase the previous one.
	meta, _ := h.manager.DB().SecretMeta(ctx, loc)
	if meta.CurrentVersion != 2 {
		t.Fatalf("the secret is at version %d, want 2", meta.CurrentVersion)
	}
}

// A file the parser refuses must be reported with the parser's own words, and
// nothing must be written.
func TestRefusedFileWritesNothing(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	resp := h.upload(t, "/coffres/"+vault.ID+"/import", "secrets.yaml",
		"mqtt:\n  password: s3cr3t\n", nil)

	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "erreur=") {
		t.Fatalf("a nested file was accepted: %q", loc)
	}
	if !strings.Contains(loc, "ligne") {
		t.Fatalf("the error does not name the line: %q", loc)
	}

	secrets, _ := h.manager.DB().ListSecrets(ctx, vault.ID, store.DefaultEnvironment)
	if len(secrets) != 0 {
		t.Fatalf("%d secrets were written despite the refusal", len(secrets))
	}
}

// Importing is writing, so a reader must not reach it.
func TestReaderCannotImport(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	if err := h.manager.DB().SetVaultMember(ctx, vault.ID, alice.ID, store.RoleReader, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	h.signInAs(t, "alice")

	if resp := h.get(t, "/coffres/"+vault.ID+"/import"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a reader reached the import page (%d)", resp.StatusCode)
	}
	resp := h.upload(t, "/coffres/"+vault.ID+"/import", "secrets.yaml", secretsYAML, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a reader imported a file (%d)", resp.StatusCode)
	}

	secrets, _ := h.manager.DB().ListSecrets(ctx, vault.ID, store.DefaultEnvironment)
	if len(secrets) != 0 {
		t.Fatal("a reader's import wrote secrets")
	}
}

// The uploaded file must never reach the server's disk. Above the in-memory
// limit, ParseMultipartForm spills to a temporary file - which for this route
// would mean a plaintext copy of every household password in the operating
// system's temporary directory.
func TestUploadNeverSpillsToDisk(t *testing.T) {
	if multipartMemory < maxRequestBytes {
		t.Fatalf("multipartMemory is %d and maxRequestBytes %d: an upload could be written to disk",
			multipartMemory, maxRequestBytes)
	}
}

// A filename is chosen by the client. It is shown back and written to the
// audit log, so it must not be trusted to be a reasonable length.
func TestOversizedFilenameIsBounded(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	// Long enough to be unreasonable, short enough that the multipart header
	// itself is still accepted: the point is what SYNSEC keeps, not what the
	// transport rejects.
	long := strings.Repeat("a", 300) + ".yaml"
	h.upload(t, "/coffres/"+vault.ID+"/import", long, secretsYAML, nil)

	entries, err := h.manager.DB().ListAudit(ctx, store.AuditFilter{Action: "secret.import"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d import entries logged", len(entries))
	}
	if len(entries[0].Detail) > 200 {
		t.Fatalf("the audit detail is %d bytes long", len(entries[0].Detail))
	}

	// And shortening the name must not change how the file was read: cutting
	// a long name drops its extension, which would turn a secrets.yaml into an
	// env file without a word.
	secrets, _ := h.manager.DB().ListSecrets(ctx, vault.ID, store.DefaultEnvironment)
	if len(secrets) != 2 {
		t.Fatalf("%d secrets imported: the format was decided from the shortened name", len(secrets))
	}
}
