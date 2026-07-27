package main

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"synsec/internal/tlsconf"
)

// testCertificate produces a throwaway certificate for the TLS half.
func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	local, err := tlsconf.EnsureLocal(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureLocal: %v", err)
	}
	return local.Certificate
}

// dial opens a raw connection to a listener's address.
func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dialling %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// newSplitServer starts a split listener with a TLS server behind it and the
// redirector in front, mirroring what serve does.
func newSplitServer(t *testing.T) string {
	t.Helper()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	listener := newSplitListener(base)
	t.Cleanup(func() { listener.Close() })

	redirector := &http.Server{Handler: httpsRedirect()}
	t.Cleanup(func() { redirector.Close() })
	go redirector.Serve(listener.Plain())

	// A certificate is needed for the TLS half; the test only checks that
	// plain HTTP never reaches it.
	tlsServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("secret"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}},
	}
	t.Cleanup(func() { tlsServer.Close() })
	go tlsServer.ServeTLS(listener, "", "")

	return base.Addr().String()
}

// A browser given "host:port" presumes http, and must be sent to https rather
// than shown an unexplained connection error.
func TestPlainRequestIsRedirectedToHTTPS(t *testing.T) {
	addr := newSplitServer(t)
	conn := dial(t, addr)

	request := "GET /coffres/abc?x=1 HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("writing request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer resp.Body.Close()

	// 308 rather than 301, so a device posting a secret retries as a POST
	// instead of silently turning it into a GET.
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status is %d, want 308", resp.StatusCode)
	}

	want := "https://" + addr + "/coffres/abc?x=1"
	if got := resp.Header.Get("Location"); got != want {
		t.Fatalf("redirected to %q, want %q", got, want)
	}
}

// The redirector answers the redirect and nothing else: no page, no secret.
func TestPlainRequestNeverReachesTheApplication(t *testing.T) {
	addr := newSplitServer(t)
	conn := dial(t, addr)

	request := "GET / HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(request))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer resp.Body.Close()

	body := make([]byte, 512)
	n, _ := resp.Body.Read(body)
	if strings.Contains(string(body[:n]), "secret") {
		t.Fatal("the application answered over plain HTTP")
	}
}

// And a real TLS client still gets through the same port.
func TestTLSStillReachesTheApplication(t *testing.T) {
	addr := newSplitServer(t)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificate
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("TLS request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the application answered %d over TLS", resp.StatusCode)
	}
}

// A connection that says nothing must not hold the accept loop open forever.
func TestSilentConnectionIsDropped(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	listener := newSplitListener(base)
	defer listener.Close()

	accepted := make(chan struct{})
	go func() {
		listener.Accept() //nolint:errcheck // the test only cares that it returns
		close(accepted)
	}()

	conn := dial(t, base.Addr().String())
	_ = conn

	// Accept must still be waiting: the silent connection was neither served
	// nor allowed to satisfy it.
	select {
	case <-accepted:
		t.Fatal("a connection that sent nothing was accepted as TLS")
	case <-time.After(300 * time.Millisecond):
	}
}
