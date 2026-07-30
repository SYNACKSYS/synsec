package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"synsec/internal/alert"
	"synsec/internal/api"
	"synsec/internal/clientip"
	"synsec/internal/config"
	"synsec/internal/store"
	"synsec/internal/tlsconf"
	"synsec/internal/vault"
	"synsec/internal/web"
)

// Server timeouts. Generous enough for a slow device on Wi-Fi, tight enough
// that a stalled connection cannot pin a goroutine forever.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 2 * time.Minute
	shutdownGrace     = 15 * time.Second
)

func runServe(args []string) error { return serve(args, nil) }

// serve runs the server until stop is closed or the process is interrupted.
//
// The stop channel exists for the Windows service, which is told to shut down
// by the service control manager rather than by a signal. A non-nil stop is
// therefore also how serve knows it has no console to report to.
func serve(args []string, stop <-chan struct{}) error {
	err := runServer(args, stop)
	if err != nil && stop != nil {
		// Under a service manager this is the only trace the owner will ever
		// see of why SYNSEC refused to start.
		log.Printf("erreur fatale : %v", err)
	}
	return err
}

// logToFile redirects the log into the data directory.
//
// A service writes to a standard error that goes nowhere. Without this, a
// failure to unseal shows up as a service that simply will not run, with no
// explanation anywhere - which is precisely the situation a non-technical
// owner has no way out of.
//
// The file is deliberately never closed. It stays open for the life of the
// process, because the last thing written to it is the fatal error reported
// after the server has already returned: closing it on the way out would
// discard exactly the line worth having.
func logToFile(dir string) error {
	path := filepath.Join(dir, "synsec.log")

	// 0600: the log names vaults and paths, never values, but it is nobody
	// else's business either.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("ouverture du journal %s : %w", path, err)
	}

	// A byte-order mark on a new file, so `type` and Notepad render the
	// accented French correctly instead of mojibake. Windows consoles still
	// default to a legacy code page, and a log nobody can read is not much
	// better than no log.
	if info, err := f.Stat(); err == nil && info.Size() == 0 {
		f.Write([]byte{0xEF, 0xBB, 0xBF})
	}

	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
	return nil
}

func runServer(args []string, stop <-chan struct{}) error {
	cfg := config.Default()

	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	apply := serveOptions(fs, &cfg)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec serve - démarre le serveur

Options :
`)+"\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	apply()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Prepare(); err != nil {
		return err
	}

	// Set up before anything that can fail, so the first failure is the first
	// thing in the log rather than the thing that prevented a log existing.
	if stop != nil {
		if err := logToFile(cfg.DataDir); err != nil {
			return err
		}
		log.Printf("démarrage du service, dossier de données %s", cfg.DataDir)
	}

	db, err := store.Open(cfg.DatabasePath())
	if err != nil {
		return err
	}
	defer db.Close()

	manager := vault.New(db, cfg.DataDir)
	ctx := context.Background()

	ready, err := manager.Initialized(ctx)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("ce serveur n'est pas encore préparé - lance d'abord : synsec init")
	}

	// Unattended unseal. This is the step that lets the house come back up
	// after a power cut with nobody at the keyboard.
	if err := manager.Unseal(ctx); err != nil {
		return fmt.Errorf("impossible d'ouvrir le coffre : %w\n"+
			"        Si cette machine a été réinstallée ou si le compte de service a changé,\n"+
			"        utilise le code de récupération imprimé à l'installation", err)
	}
	defer manager.Seal()

	// Sessions expirées et vieilles lignes de journal : sans ce ménage, les
	// deux tables croissent sans fin et un disque plein arrête le serveur.
	janitorCtx, stopJanitor := context.WithCancel(ctx)
	defer stopJanitor()
	startJanitor(janitorCtx, db, cfg.AuditRetain)

	// Les alertes suivent le journal plutôt que les gestionnaires : c'est ce
	// qui fait qu'une suppression lancée en ligne de commande, service arrêté,
	// est signalée au redémarrage comme le reste.
	hostname, _ := os.Hostname()
	watcher := alert.NewWatcher(db, func(ctx context.Context) (alert.Config, error) {
		return alert.LoadConfig(ctx, manager, hostname)
	})
	go watcher.Run(janitorCtx)

	// Qui a le droit de dire d'où vient une requête. Sans proxy nommé,
	// X-Forwarded-For est ignoré : sinon n'importe quel appelant choisirait
	// l'adresse contre laquelle ses listes blanches sont vérifiées.
	clients, err := clientip.New(cfg.TrustedProxies)
	if err != nil {
		return fmt.Errorf("proxies de confiance : %w", err)
	}
	for _, entry := range cfg.WebAllow {
		if _, err := store.ParseNetwork(entry); err != nil {
			return fmt.Errorf("adresse autorisée sur l'interface : %w", err)
		}
	}

	apiOpts := []api.Option{api.TrustProxies(clients)}

	// Prepared before the interface, because the names this certificate covers
	// are what let the interface tell an address it really serves from one a
	// caller merely claimed in a Host header.
	tlsConf, local, err := serverTLS(cfg)
	if err != nil {
		return err
	}
	servedNames := servedCertificateNames(cfg, local)

	ui, err := web.New(manager,
		web.WithSessionIdle(cfg.SessionIdle),
		// The names the certificate covers, so the interface can tell an
		// address it really serves from one a caller merely claimed.
		web.ServedNames(servedNames),
		web.TrustProxies(clients),
		web.RestrictTo(cfg.WebAllow),
		web.RequireSecondFactor(cfg.RequireSecondFactor),
		web.WithAlerts(watcher),
	)
	if err != nil {
		return err
	}

	// The API and the interface share one port: asking a household to
	// remember two would be one thing too many.
	root := http.NewServeMux()
	root.Handle("/api/", api.New(manager, apiOpts...).Handler())
	root.Handle("/", ui.Handler())

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           root,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
	}

	srv.TLSConfig = tlsConf
	announce(cfg, local)

	return listenAndServe(srv, cfg, stop)
}

func listenAndServe(srv *http.Server, cfg config.Config, stop <-chan struct{}) error {
	base, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("impossible d'écouter sur %s : %w", cfg.Listen, err)
	}

	// Connections are sorted by their first byte: TLS to the real server,
	// everything else to a redirector that answers nothing but "go to HTTPS".
	listener := newSplitListener(base)
	defer listener.Close()

	redirector := &http.Server{
		Handler:           httpsRedirect(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		ErrorLog:          srv.ErrorLog,
	}
	defer redirector.Close()
	go redirector.Serve(listener.Plain()) //nolint:errcheck // ends with the listener

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	errs := make(chan error, 1)
	go func() {
		errs <- srv.ServeTLS(listener, "", "")
	}()

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-signals:
	case <-stop:
	}

	// Shutdown is graceful so that a device mid-request gets its answer rather
	// than a reset connection it will report as a failure.
	log.Println("arrêt en cours...")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("arrêt : %w", err)
	}
	return nil
}

// serverTLS builds the TLS settings: the operator's own certificate if they
// configured one, otherwise SYNSEC's local authority.
//
// A configured certificate is served through a reloader, so a renewal is
// picked up without restarting. The self-signed one needs no such thing - it
// only changes when SYNSEC itself regenerates it, which happens at startup.
func serverTLS(cfg config.Config) (*tls.Config, *tlsconf.Local, error) {
	if cfg.TLSCert != "" {
		reloader, err := tlsconf.NewReloader(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, nil, err
		}
		return &tls.Config{
			GetCertificate: reloader.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}, nil, nil
	}

	local, err := tlsconf.EnsureLocal(cfg.DataDir)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{local.Certificate},
		MinVersion:   tls.VersionTLS12,
	}, &local, nil
}

// servedCertificateNames lists the addresses the served certificate covers.
//
// With SYNSEC's own certificate they are read from it directly. With an
// operator's certificate the file is read once here: it is the same file the
// reloader serves, and its names change only when the certificate itself does.
// A file that cannot be read leaves the list empty, which keeps the previous
// behaviour rather than turning a certificate problem into a broken page.
func servedCertificateNames(cfg config.Config, local *tlsconf.Local) []string {
	if local != nil {
		return tlsconf.ServedNames(local.Certificate)
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		log.Printf("serve: reading the certificate names: %v", err)
		return nil
	}
	return tlsconf.ServedNames(cert)
}

func announce(cfg config.Config, local *tlsconf.Local) {
	fmt.Printf("SYNSEC écoute sur https://%s\n", displayAddr(cfg.Listen))
	fmt.Println("Une adresse tapée en http est automatiquement renvoyée vers https.")

	if local == nil || !local.Fresh {
		return
	}

	// Until the certificate is installed, every client refuses the connection -
	// browsers with a warning, PowerShell with an error that says nothing
	// useful. Telling the owner what to run, here and now, is the difference
	// between a working install and an afternoon lost.
	fmt.Println()
	fmt.Println("Un certificat vient d'être créé pour cette machine.")
	fmt.Println("Tant qu'il n'est pas installé, ton navigateur affichera un")
	fmt.Println("avertissement et PowerShell refusera de se connecter.")
	fmt.Println()
	fmt.Println("Pour le faire accepter, dans une invite administrateur :")
	fmt.Println()
	fmt.Println("    synsec cert trust")
	fmt.Println()
	fmt.Printf("Empreinte SHA-256 : %s\n", local.Fingerprint)
	fmt.Println()
}

// displayAddr turns a bind address into something a person can paste into a
// browser: ":8787" alone is not a URL anyone can use.
func displayAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		if name, err := os.Hostname(); err == nil && name != "" {
			return net.JoinHostPort(name, port)
		}
		return net.JoinHostPort("localhost", port)
	}
	return listen
}
