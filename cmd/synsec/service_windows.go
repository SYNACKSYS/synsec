//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"synsec/internal/config"
)

// serviceModeRequested reports whether the service control manager started us.
//
// A process launched by the SCM has no console and must answer the service
// protocol within about thirty seconds, or Windows kills it with error 1053 -
// which is why a plain console program cannot simply be registered as a
// service.
func serviceModeRequested() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

type synsecService struct {
	args []string
}

func (s *synsecService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	errs := make(chan error, 1)
	go func() { errs <- serve(s.args, stop) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(stop)
				<-errs // let connections in flight finish
				return false, 0
			}
		case err := <-errs:
			// The server stopped on its own: a bind failure, or a vault that
			// would not unseal. Report it as a service failure so Windows
			// applies the restart policy.
			changes <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}

func runServiceMode(args []string) error {
	// The service is registered with "serve" and its options; strip the
	// subcommand so serve sees only its own flags.
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	return svc.Run(serviceName, &synsecService{args: args})
}

func installService(cfg config.Config) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("chemin de l'exécutable : %w", err)
	}

	m, err := connectManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		return fmt.Errorf("le service %s est déjà installé\n"+
			"        Pour le remplacer :  synsec service uninstall", serviceName)
	}

	args := serveArgs(cfg)

	service, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "SYNSEC - serveur de secrets",
		Description:  "Fournit aux appareils du réseau les secrets de la maison.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, args...)
	if err != nil {
		return fmt.Errorf("création du service : %w", err)
	}
	defer service.Close()

	// A home server has nobody watching it. If it dies at three in the
	// morning it has to come back on its own, and keep trying.
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400); err != nil {
		// Not fatal: the service works, it simply will not revive itself.
		fmt.Fprintf(os.Stderr, "note : redémarrage automatique non configuré (%v)\n", err)
	}

	if err := service.Start(); err != nil {
		return fmt.Errorf("le service est installé mais n'a pas démarré : %w\n"+
			"        Regarde l'observateur d'événements, ou lance :  synsec serve -data %s", err, cfg.DataDir)
	}
	return nil
}

func uninstallService() error {
	m, err := connectManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("le service %s n'est pas installé", serviceName)
	}
	defer service.Close()

	if _, err := service.Control(svc.Stop); err == nil {
		waitForState(service, svc.Stopped, 20*time.Second)
	}
	if err := service.Delete(); err != nil {
		return fmt.Errorf("suppression du service : %w", err)
	}
	return nil
}

func serviceStatus() (string, error) {
	m, err := connectManager()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()

	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Sprintf("Le service %s n'est pas installé.\n"+
			"Pour l'installer :  synsec service install", serviceName), nil
	}
	defer service.Close()

	status, err := service.Query()
	if err != nil {
		return "", fmt.Errorf("état du service : %w", err)
	}

	config, err := service.Config()
	if err != nil {
		return describeState(status.State), nil
	}
	return fmt.Sprintf("Service %s : %s\nDémarrage : %s\nCommande : %s",
		serviceName, describeState(status.State),
		describeStartType(config.StartType), config.BinaryPathName), nil
}

func connectManager() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("accès au gestionnaire de services refusé : %w\n"+
			"        Ouvre une invite de commande en tant qu'administrateur", err)
	}
	return m, nil
}

func waitForState(service *mgr.Service, want svc.State, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil || status.State == want {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func describeState(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "arrêté"
	case svc.StartPending:
		return "démarrage en cours"
	case svc.StopPending:
		return "arrêt en cours"
	case svc.Running:
		return "en fonctionnement"
	case svc.Paused:
		return "en pause"
	default:
		return "état inconnu"
	}
}

func describeStartType(startType uint32) string {
	switch startType {
	case mgr.StartAutomatic:
		return "automatique"
	case mgr.StartManual:
		return "manuel"
	case mgr.StartDisabled:
		return "désactivé"
	default:
		return "inconnu"
	}
}
