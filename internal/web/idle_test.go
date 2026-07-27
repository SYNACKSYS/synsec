package web

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a hand-wound time source, so a test can sit idle for an hour
// without taking one.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Now()} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

const testIdle = 30 * time.Minute

func TestSessionLapsesWhenLeftAlone(t *testing.T) {
	c := newClock()
	h := newHarness(t, withClock(c.Now), WithSessionIdle(testIdle))
	h.signIn(t)

	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("a fresh session was refused (%d)", resp.StatusCode)
	}

	c.advance(testIdle + time.Minute)

	resp := h.get(t, "/")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("an idle session was still accepted (%d)", resp.StatusCode)
	}
	// Sent back with a reason: "why am I on the login page" is a worse
	// experience than being told the tab sat too long.
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "expiree") {
		t.Fatalf("the visitor was not told why: %q", loc)
	}

	// And the login page says so in words.
	if page := body(t, h.get(t, "/login?expiree=1")); !strings.Contains(page, "30 minutes") {
		t.Fatal("the login page does not mention the timeout")
	}
}

// Every page seen pushes the timeout back, so an interface in use never lapses
// under someone's hands. This is the half that makes a short timeout bearable.
func TestActivityKeepsTheSessionAlive(t *testing.T) {
	c := newClock()
	h := newHarness(t, withClock(c.Now), WithSessionIdle(testIdle))
	h.signIn(t)

	// Well past the timeout in total, but never idle for more than half of it.
	for i := 0; i < 6; i++ {
		c.advance(testIdle / 2)
		if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
			t.Fatalf("signed out after %d refreshes while still active (%d)", i, resp.StatusCode)
		}
	}

	// Then stop, and it lapses like any other.
	c.advance(testIdle + time.Minute)
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the session outlived its idle timeout (%d)", resp.StatusCode)
	}
}

// The cookie has to be reissued too. Set once at sign-in, its own Expires
// would run out while the server still held the session live, and the browser
// would drop it mid-use.
func TestActivityAlsoPushesTheCookie(t *testing.T) {
	c := newClock()
	h := newHarness(t, withClock(c.Now), WithSessionIdle(testIdle))
	h.signIn(t)

	first := sessionCookieExpiry(t, h.get(t, "/"))
	c.advance(10 * time.Minute)
	second := sessionCookieExpiry(t, h.get(t, "/"))

	if !second.After(first) {
		t.Fatalf("the cookie still expires at %v after ten minutes of use (was %v)", second, first)
	}
	if got := second.Sub(first); got < 9*time.Minute || got > 11*time.Minute {
		t.Fatalf("the cookie moved by %v, want about the ten minutes that passed", got)
	}
}

// Signing out is not a lapsed session, so the login page must not blame one.
func TestSignOutIsNotReportedAsATimeout(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/logout", url.Values{"csrf": {h.csrf(t)}})
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "expiree") {
		t.Fatalf("a deliberate sign-out was reported as a timeout: %q", loc)
	}
}

func sessionCookieExpiry(t *testing.T, resp *http.Response) time.Time {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c.Expires
		}
	}
	t.Fatal("the response did not reissue the session cookie")
	return time.Time{}
}
