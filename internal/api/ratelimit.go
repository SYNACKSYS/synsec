package api

import (
	"net/http"
	"sync"
	"time"
)

// Rate limiting for the machine-facing surface.
//
// The web interface has always throttled sign-ins; the API had nothing. On a
// home network that was defensible: a device polls a few times a minute and
// the only caller is the household. Reachable from anywhere it is not, and the
// gap it leaves is not credential guessing - a token secret is 256 random bits
// and no amount of trying will find one - but everything around it. Every
// attempt costs a database read, a failed one against a known identifier costs
// an audit write, and enough of them fill a disk or drown the log that an
// intrusion would otherwise stand out in.
//
// A token bucket per address: a burst is absorbed, a sustained flood is
// slowed to the rate a real device needs and no more.
const (
	// burstPerAddress is what a device may spend at once. Home Assistant
	// fetching a handful of secrets at start-up is the shape to accommodate.
	burstPerAddress = 30

	// refillPerSecond is the sustained rate. Two a second is far above any
	// polling interval worth having and far below what hurts.
	refillPerSecond = 2

	// forgetAfter drops an address that has gone quiet, so the table tracks
	// the callers there are rather than every address ever seen.
	forgetAfter = 10 * time.Minute
)

// limiter hands out permission to make a request.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{buckets: make(map[string]*bucket), now: now}
}

// allow reports whether an address may make one more request.
func (l *limiter) allow(address string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, seen := l.buckets[address]
	if !seen {
		// Sweeping here rather than on a timer: the only moment the table can
		// grow is when a new address arrives, so that is the moment to look.
		l.forgetIdle(now)

		b = &bucket{tokens: burstPerAddress}
		l.buckets[address] = b
	}

	if !b.lastSeen.IsZero() {
		b.tokens += now.Sub(b.lastSeen).Seconds() * refillPerSecond
		if b.tokens > burstPerAddress {
			b.tokens = burstPerAddress
		}
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) forgetIdle(now time.Time) {
	for address, b := range l.buckets {
		if now.Sub(b.lastSeen) > forgetAfter {
			delete(l.buckets, address)
		}
	}
}

// limit refuses a caller that is asking too fast.
//
// Placed before authentication, so a flood of unauthenticated requests is
// turned away without the database being consulted at all. The answer carries
// Retry-After, because a device that is told to wait should be able to.
func (s *Server) limit(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, codeTooManyRequests,
				"too many requests")
			return
		}
		h(w, r)
	}
}
