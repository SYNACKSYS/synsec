package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// SYNSEC listens on a single port and serves TLS on it. A caller who arrives
// in plain HTTP - a browser given "HV-01:8787", which presumes http:// - is
// sent to the same address over HTTPS rather than refused.
//
// A refusal would be the stricter reading, but it produces an unexplained
// connection error and invites people to look for a way around it. The
// redirect is the only thing ever answered without TLS: no page, no secret and
// no cookie is served in clear, and the request body is never even read.

const (
	// tlsRecordHandshake is the first byte of every TLS ClientHello.
	tlsRecordHandshake = 0x16

	// peekTimeout bounds how long a connection may sit without saying which
	// protocol it speaks.
	peekTimeout = 10 * time.Second

	// plainBacklog caps the connections waiting to be redirected.
	plainBacklog = 32

	// tlsBacklog caps the classified connections waiting for the TLS server to
	// pick them up.
	tlsBacklog = 64

	// maxSorting caps how many connections may be identifying themselves at
	// once. Each costs a goroutine and one byte of buffer for up to
	// peekTimeout, so this is what a flood of silent connections can spend.
	maxSorting = 256
)

// splitListener routes each accepted connection by its first byte: TLS
// handshakes go to the real server, everything else to the redirector.
type splitListener struct {
	net.Listener

	tls       chan net.Conn
	plain     chan net.Conn
	sorting   chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
	once      sync.Once
}

func newSplitListener(inner net.Listener) *splitListener {
	return &splitListener{
		Listener: inner,
		tls:      make(chan net.Conn, tlsBacklog),
		plain:    make(chan net.Conn, plainBacklog),
		sorting:  make(chan struct{}, maxSorting),
		closed:   make(chan struct{}),
	}
}

// sort reads the accept queue and classifies each connection off the critical
// path.
//
// The peek must not happen in Accept. Reading the first byte waits up to
// peekTimeout, and a client that connects without sending anything would hold
// the accept loop for that whole time - one idle socket, repeated, and the
// server stops answering everybody. Classification therefore runs in its own
// goroutine per connection, bounded by maxSorting so that a flood costs memory
// rather than availability.
func (l *splitListener) sort() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			close(l.tls) // wakes Accept, which reports the failure
			return
		}

		select {
		case l.sorting <- struct{}{}:
		case <-l.closed:
			conn.Close()
			return
		default:
			// More connections are waiting to identify themselves than this
			// server has any reason to see. Dropping the newest keeps the ones
			// already being classified.
			conn.Close()
			continue
		}

		go func() {
			defer func() { <-l.sorting }()

			peeked, isTLS, err := peekProtocol(conn)
			if err != nil {
				conn.Close()
				return
			}

			queue := l.plain
			if isTLS {
				queue = l.tls
			}
			select {
			case queue <- peeked:
			case <-l.closed:
				peeked.Close()
			default:
				// Saturated. Dropping beats blocking a goroutine that holds a
				// classification slot.
				peeked.Close()
			}
		}()
	}
}

// Accept returns only TLS connections; the plain ones go to the redirector.
func (l *splitListener) Accept() (net.Conn, error) {
	l.once.Do(func() { go l.sort() })

	select {
	case conn, ok := <-l.tls:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *splitListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

// Plain is the listener the redirector serves.
func (l *splitListener) Plain() net.Listener {
	return &plainListener{source: l}
}

// plainListener presents the non-TLS connections as a listener of their own.
type plainListener struct {
	source *splitListener
}

func (p *plainListener) Accept() (net.Conn, error) {
	select {
	case conn := <-p.source.plain:
		return conn, nil
	case <-p.source.closed:
		return nil, net.ErrClosed
	}
}

func (p *plainListener) Close() error   { return nil }
func (p *plainListener) Addr() net.Addr { return p.source.Addr() }

// peekProtocol reads the first byte to tell a TLS handshake from anything
// else, and returns a connection that will replay it.
func peekProtocol(conn net.Conn) (net.Conn, bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(peekTimeout)); err != nil {
		return nil, false, err
	}

	first := make([]byte, 1)
	n, err := conn.Read(first)
	if err != nil || n == 0 {
		return nil, false, err
	}

	// The deadline was for the peek alone; the server sets its own afterwards.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, false, err
	}
	return &peekedConn{Conn: conn, prefix: first[:n]}, first[0] == tlsRecordHandshake, nil
}

// peekedConn hands back the bytes already read before deferring to the
// connection underneath.
type peekedConn struct {
	net.Conn
	prefix []byte
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// httpsRedirect answers every plain-HTTP request with a permanent redirect to
// the same address over TLS, and answers nothing else.
func httpsRedirect() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			// Nothing else is known about where the caller meant to go.
			http.Error(w, "SYNSEC ne répond qu'en HTTPS.", http.StatusBadRequest)
			return
		}

		// Same host and port, since TLS is served on this very listener.
		target := "https://" + host + r.URL.RequestURI()

		// 308 rather than 301: it preserves the method, so a device posting a
		// secret retries as a POST instead of silently turning it into a GET.
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}
