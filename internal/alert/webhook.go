package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Sending to a webhook.
//
// A POST of JSON, signed, to an address the owner chose. No third party, no
// quota, no mail server to keep alive - and on a household network the
// receiver is usually Home Assistant or ntfy, three metres away.

const (
	// signatureHeader carries the proof that this came from this server.
	signatureHeader = "X-SYNSEC-Signature"
	// timestampHeader is signed along with the body, so a message captured
	// once cannot be replayed a week later as fresh news.
	timestampHeader = "X-SYNSEC-Timestamp"

	sendTimeout = 10 * time.Second
	maxAttempts = 3
)

// Webhook is a configured destination.
type Webhook struct {
	URL string
	// Secret signs the messages. The receiver checks the signature; without
	// one, anything able to reach the receiver could invent an alert - or,
	// worse, drown a real one in noise.
	Secret string

	// Client is exposed so tests can hand in their own. Nil means a plain
	// client with a timeout.
	Client *http.Client
	// Server names this installation in the message, so somebody running two
	// can tell them apart.
	Server string
	Now    func() time.Time
}

// ErrNoDestination means nothing is configured, which is not a failure: a
// server with no webhook set simply does not send.
var ErrNoDestination = errors.New("alert: aucune destination configurée")

// ValidateURL reports whether an address can be posted to.
//
// http and https only. Not a security boundary - the receiver is meant to be
// on the same network, so blocking private addresses would block the normal
// case - but a scheme the sender cannot speak is a typo worth catching while
// somebody is looking at the form, rather than at three in the morning when
// the alert does not arrive.
func ValidateURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ErrNoDestination
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("adresse illisible : %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("adresse en %q : SYNSEC ne sait envoyer qu'en http ou https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("adresse sans machine : il manque le nom ou l'IP du destinataire")
	}
	return nil
}

// send posts one message, retrying a couple of times on a network failure.
func (w Webhook) send(ctx context.Context, m message) error {
	if err := ValidateURL(w.URL); err != nil {
		return err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("alert: encoding the message: %w", err)
	}

	client := w.Client
	if client == nil {
		client = &http.Client{
			Timeout: sendTimeout,
			// Redirects are not followed. An alert carries the names of
			// vaults and secrets, and a receiver that starts answering "go
			// ask over there instead" is either misconfigured or has been
			// taken over; either way this is not the moment to obey it.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	var last error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := w.post(ctx, client, body)
		if err == nil {
			return nil
		}
		last = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A refusal from the receiver is an answer: it was reached and said
		// no, and trying again will produce the same no.
		var refused refusal
		if errors.As(err, &refused) {
			return err
		}
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
	}
	return last
}

// refusal is an answer from the receiver rather than a failure to reach it.
type refusal struct {
	status int
	body   string
}

func (r refusal) Error() string {
	if r.body != "" {
		return fmt.Sprintf("le destinataire a répondu %d : %s", r.status, r.body)
	}
	return fmt.Sprintf("le destinataire a répondu %d", r.status)
}

func (w Webhook) post(ctx context.Context, client *http.Client, body []byte) error {
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	stamp := strconv.FormatInt(now().Unix(), 10)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("alert: building the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SYNSEC")
	req.Header.Set(timestampHeader, stamp)
	if w.Secret != "" {
		req.Header.Set(signatureHeader, Sign(w.Secret, stamp, body))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("destinataire injoignable : %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck // draining to reuse the connection
		return nil
	}
	// Enough of the answer to be diagnosable, not enough to fill the log with
	// somebody's error page.
	said, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	return refusal{status: resp.StatusCode, body: strings.TrimSpace(string(said))}
}

// Sign computes the signature of a message.
//
// Over the timestamp and the body together, so neither can be swapped for
// another: a signature covering only the body would let a message from last
// month be replayed today with a fresh timestamp.
//
// Exported because the receiving end has to compute the same thing, and the
// documentation shows this function's shape in three lines of any language.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
