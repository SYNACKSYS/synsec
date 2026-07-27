package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeServer stands in for SYNSEC: it speaks the same two endpoints and checks
// the credential arrives the way the real one insists on.
type fakeServer struct {
	*httptest.Server
	secrets map[string]string
	reads   []string
}

func newFakeServer(t *testing.T, secrets map[string]string) *fakeServer {
	t.Helper()
	f := &fakeServer{secrets: secrets}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorised(w, r) {
			return
		}
		type summary struct {
			Name string `json:"name"`
		}
		out := make([]summary, 0, len(f.secrets))
		for name := range f.secrets {
			out = append(out, summary{Name: name})
		}
		json.NewEncoder(w).Encode(map[string]any{"secrets": out})
	})
	mux.HandleFunc("/api/v1/secrets/value", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorised(w, r) {
			return
		}
		name := r.URL.Query().Get("name")
		value, ok := f.secrets[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(apiError{Code: "not_found", Message: "no such secret"})
			return
		}
		f.reads = append(f.reads, name)
		json.NewEncoder(w).Encode(secretValue{Name: name, Value: value})
	})

	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) authorised(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer syn_test" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(apiError{Code: "unauthorized", Message: "no"})
		return false
	}
	return true
}

// client returns an agent client wired to this server, trusting its throwaway
// certificate the way -ca would.
func (f *fakeServer) client(t *testing.T) *client {
	t.Helper()
	return &client{
		addr:  f.URL,
		token: "syn_test",
		http:  f.Server.Client(),
	}
}

func TestEnvName(t *testing.T) {
	cases := map[string]string{
		"mot_de_passe_mqtt": "MOT_DE_PASSE_MQTT",
		"cle-wifi":          "CLE_WIFI",
		"home_assistant":    "HOME_ASSISTANT",
		"api.key":           "API_KEY",
		"_leading":          "LEADING",
		"2fa_seed":          "_2FA_SEED",
		"a  b":              "A_B",
	}
	for secret, want := range cases {
		if got := envName("", secret); got != want {
			t.Errorf("envName(%q) = %q, want %q", secret, got, want)
		}
	}

	if got := envName("APP_", "mqtt_password"); got != "APP_MQTT_PASSWORD" {
		t.Errorf("the prefix was not applied: %q", got)
	}
}

// Two identifiers that differ only by punctuation land on the same variable.
// Letting one silently win would hand a service the wrong secret.
func TestCollisionIsReported(t *testing.T) {
	_, _, clash := collide("", []string{"mqtt-password", "mqtt_password"})
	if !clash {
		t.Fatal("a collision went unreported")
	}
	if _, _, clash := collide("", []string{"mqtt_password", "cle_wifi"}); clash {
		t.Fatal("distinct names were reported as colliding")
	}
}

func TestFetchAsksForEachSecretSeparately(t *testing.T) {
	f := newFakeServer(t, map[string]string{
		"mqtt_password": "s3cr3t",
		"cle_wifi":      "hunter2",
	})

	names, err := f.client(t).list(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("the listing returned %v", names)
	}

	values, err := f.client(t).fetch(context.Background(), names)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if values["mqtt_password"] != "s3cr3t" || values["cle_wifi"] != "hunter2" {
		t.Fatalf("the values came back wrong: %v", values)
	}
	if len(f.reads) != 2 {
		t.Fatalf("%d value requests were made, want one per secret", len(f.reads))
	}
}

func TestRefusalsAreExplained(t *testing.T) {
	f := newFakeServer(t, map[string]string{"mqtt_password": "s3cr3t"})

	wrong := &client{addr: f.URL, token: "syn_faux", http: f.Server.Client()}
	if _, err := wrong.list(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "refusé") {
		t.Fatalf("a rejected token gave %v", err)
	}

	if _, err := f.client(t).value(context.Background(), "nexistepas"); err == nil ||
		!strings.Contains(err.Error(), "n'existe pas") {
		t.Fatalf("an unknown secret gave %v", err)
	}
}

// The environment is built from the parent's, with the secrets on top.
func TestEnvironWith(t *testing.T) {
	base := []string{"PATH=/usr/bin", "MQTT_PASSWORD=ancien"}
	out := environWith(base, "", map[string]string{"mqtt_password": "nouveau"})

	var seenPath, seenNew bool
	for _, entry := range out {
		switch entry {
		case "PATH=/usr/bin":
			seenPath = true
		case "MQTT_PASSWORD=nouveau":
			seenNew = true
		case "MQTT_PASSWORD=ancien":
			t.Fatal("the inherited value survived alongside the secret")
		}
	}
	if !seenPath {
		t.Fatal("the parent environment was dropped")
	}
	if !seenNew {
		t.Fatal("the secret was not injected")
	}
}

// A value holding quotes must survive the shell it is handed to.
func TestQuoting(t *testing.T) {
	values := map[string]string{"awkward": `a'b"c\d $HOME` + "\n"}

	sh, err := render("sh", "", values)
	if err != nil {
		t.Fatalf("render sh: %v", err)
	}
	if !strings.HasPrefix(sh, "export AWKWARD='a'\\''b") {
		t.Fatalf("the single quote was not escaped: %q", sh)
	}
	// Inside single quotes the shell expands nothing, so the dollar sign is
	// still there, literally, for the child to receive.
	if !strings.Contains(sh, "$HOME") {
		t.Fatalf("the value was mangled: %q", sh)
	}

	ps, err := render("powershell", "", values)
	if err != nil {
		t.Fatalf("render powershell: %v", err)
	}
	if !strings.Contains(ps, "$env:AWKWARD = 'a''b") {
		t.Fatalf("the quote was not doubled: %q", ps)
	}

	dotenv, err := render("dotenv", "", values)
	if err != nil {
		t.Fatalf("render dotenv: %v", err)
	}
	if !strings.Contains(dotenv, `\"c\\d`) || !strings.Contains(dotenv, `\n`) {
		t.Fatalf("the escaping is wrong: %q", dotenv)
	}

	asJSON, err := render("json", "", values)
	if err != nil {
		t.Fatalf("render json: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(asJSON), &decoded); err != nil {
		t.Fatalf("the JSON output does not parse: %v", err)
	}
	if decoded["AWKWARD"] != values["awkward"] {
		t.Fatalf("the round trip changed the value: %q", decoded["AWKWARD"])
	}

	if _, err := render("klingon", "", values); err == nil {
		t.Fatal("an unknown format was accepted")
	}
}

func TestSplitAtDoubleDash(t *testing.T) {
	mine, child := splitAtDoubleDash([]string{"-prefix", "APP_", "--", "ls", "-l"})
	if len(mine) != 2 || mine[0] != "-prefix" {
		t.Fatalf("the agent's own options are %v", mine)
	}
	if len(child) != 2 || child[1] != "-l" {
		t.Fatalf("the child's arguments are %v", child)
	}

	mine, child = splitAtDoubleDash([]string{"-quiet"})
	if len(child) != 0 || len(mine) != 1 {
		t.Fatalf("without a separator: mine=%v child=%v", mine, child)
	}
}

// The address has to be an https one: the server has no other mode, and a
// silent failure here would look like a network problem.
func TestConfigurationIsChecked(t *testing.T) {
	cases := map[string]config{
		"sans adresse": {token: "syn_x"},
		"sans jeton":   {addr: "https://localhost:8787"},
		"en http":      {addr: "http://localhost:8787", token: "syn_x"},
	}
	for name, c := range cases {
		c.timeout = time.Second
		if _, err := newClient(&c); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}

	ok := config{addr: "https://localhost:8787/", token: "syn_x", timeout: time.Second}
	c, err := newClient(&ok)
	if err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}
	if strings.HasSuffix(c.addr, "/") {
		t.Fatalf("the trailing slash was kept: %q", c.addr)
	}
}
