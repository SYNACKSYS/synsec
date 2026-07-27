package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// client talks to one SYNSEC server with one token.
type client struct {
	addr  string
	token string
	http  *http.Client
}

// config is what every subcommand needs before it can do anything.
type config struct {
	addr     string
	token    string
	ca       string
	insecure bool
	prefix   string
	names    string
	timeout  time.Duration
}

// bindFlags registers the options shared by every subcommand.
//
// Each one also reads an environment variable, because that is how a service
// unit, a container and a scheduled task pass configuration - and because a
// token on a command line is visible in the process list to every other user
// on the machine.
func bindFlags(fs *flag.FlagSet, c *config) {
	fs.StringVar(&c.addr, "addr", os.Getenv("SYNSEC_ADDR"), "adresse du serveur, par exemple https://192.168.1.10:8787")
	fs.StringVar(&c.token, "token", os.Getenv("SYNSEC_TOKEN"), "jeton de service (préférer la variable SYNSEC_TOKEN)")
	fs.StringVar(&c.ca, "ca", os.Getenv("SYNSEC_CA"), "certificat du serveur, si l'autorité n'est pas installée sur cette machine")
	fs.BoolVar(&c.insecure, "insecure", false, "ne pas vérifier le certificat (à éviter)")
	fs.StringVar(&c.prefix, "prefix", os.Getenv("SYNSEC_PREFIX"), "préfixe ajouté au nom de chaque variable")
	fs.StringVar(&c.names, "secret", "", "secrets à récupérer, séparés par des virgules (défaut : tous ceux du jeton)")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Second, "délai maximal par requête")
}

// newClient validates the configuration and prepares the HTTP client.
func newClient(c *config) (*client, error) {
	addr := strings.TrimRight(strings.TrimSpace(c.addr), "/")
	if addr == "" {
		return nil, errors.New("indique l'adresse du serveur avec -addr ou SYNSEC_ADDR")
	}
	parsed, err := url.Parse(addr)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("adresse illisible : %q", c.addr)
	}
	// The server has no plain-HTTP mode, so an http:// address is a mistake
	// worth naming rather than a request worth sending.
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("l'adresse doit commencer par https:// (reçu %q)", parsed.Scheme+"://")
	}

	token := strings.TrimSpace(c.token)
	if token == "" {
		return nil, errors.New("indique le jeton avec SYNSEC_TOKEN ou -token")
	}

	tlsConf, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}

	return &client{
		addr:  addr,
		token: token,
		http: &http.Client{
			Timeout:   c.timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConf},
		},
	}, nil
}

// tlsConfig builds the trust settings.
//
// SYNSEC issues its own certificate, so a machine that has not been told to
// trust it will refuse the connection - which is the correct behaviour, and
// the reason -ca exists.
func tlsConfig(c *config) (*tls.Config, error) {
	if c.insecure {
		fmt.Fprintln(os.Stderr,
			"synsec-agent : -insecure, le certificat du serveur n'est pas vérifié")
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	if c.ca == "" {
		// Nothing set: the system trust store decides, which is what
		// "synsec cert trust" prepares.
		return nil, nil
	}

	pem, err := os.ReadFile(c.ca)
	if err != nil {
		return nil, fmt.Errorf("lecture du certificat %s : %w", c.ca, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s ne contient aucun certificat lisible", c.ca)
	}
	return &tls.Config{RootCAs: pool}, nil
}

type secretSummary struct {
	Name string `json:"name"`
}

type secretValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// list returns the names this token reaches.
func (c *client) list(ctx context.Context) ([]string, error) {
	var body struct {
		Secrets []secretSummary `json:"secrets"`
	}
	if err := c.get(ctx, "/api/v1/secrets", nil, &body); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(body.Secrets))
	for _, s := range body.Secrets {
		names = append(names, s.Name)
	}
	return names, nil
}

// value returns one decrypted secret.
func (c *client) value(ctx context.Context, name string) (string, error) {
	var body secretValue
	if err := c.get(ctx, "/api/v1/secrets/value", url.Values{"name": {name}}, &body); err != nil {
		return "", err
	}
	return body.Value, nil
}

// fetch resolves the secrets a command needs, one request each.
//
// One request per entry because the API has no endpoint that returns a set of
// values, deliberately: every read is a separate line in the audit log, and a
// device that pulls everything at once would make that log unreadable.
func (c *client) fetch(ctx context.Context, names []string) (map[string]string, error) {
	out := make(map[string]string, len(names))
	for _, name := range names {
		v, err := c.value(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("secret %q : %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}

// get performs one authenticated request and decodes the answer.
func (c *client) get(ctx context.Context, path string, query url.Values, into any) error {
	target := c.addr + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	// The header, never the query string: an address ends up in proxy logs and
	// in shell history, which is exactly where a credential must not be.
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return friendlyTransportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return statusError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("réponse illisible du serveur : %w", err)
	}
	return nil
}

// statusError turns a refusal into something a person can act on.
func statusError(resp *http.Response) error {
	var body apiError
	_ = json.NewDecoder(resp.Body).Decode(&body)

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("jeton refusé : révoqué, expiré, ou mal copié")
	case http.StatusForbidden:
		if body.Code == "forbidden" && body.Message != "" {
			return errors.New(body.Message)
		}
		return errors.New("ce jeton n'a pas accès à ce secret")
	case http.StatusNotFound:
		return errors.New("ce secret n'existe pas")
	case http.StatusServiceUnavailable:
		return errors.New("le serveur est verrouillé et ne peut pas servir de secret")
	default:
		if body.Message != "" {
			return fmt.Errorf("le serveur a répondu %d : %s", resp.StatusCode, body.Message)
		}
		return fmt.Errorf("le serveur a répondu %d", resp.StatusCode)
	}
}

// friendlyTransportError names the two failures every first run hits.
func friendlyTransportError(err error) error {
	text := err.Error()
	switch {
	case strings.Contains(text, "certificate") || strings.Contains(text, "x509"):
		return fmt.Errorf("certificat refusé : installe-le avec « synsec cert trust » sur le serveur, "+
			"ou indique-le ici avec -ca\n        (%w)", err)
	case strings.Contains(text, "connection refused") || strings.Contains(text, "no such host"):
		return fmt.Errorf("serveur injoignable : vérifie -addr et que SYNSEC tourne\n        (%w)", err)
	default:
		return err
	}
}

// selectNames resolves which secrets to fetch: those named, or everything the
// token reaches.
func selectNames(ctx context.Context, c *client, requested string) ([]string, error) {
	if named := splitList(requested); len(named) > 0 {
		return named, nil
	}
	return c.list(ctx)
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
