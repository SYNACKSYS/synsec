//go:build linux

package unseal

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// credentialName scopes the sealed blob inside systemd's credential namespace,
// so a credential produced for another service cannot be swapped in.
const credentialName = "synsec"

// systemdTimeout bounds the helper call: a TPM that stops answering must not
// hang service startup indefinitely.
const systemdTimeout = 20 * time.Second

// SystemdTPM2 protects the wrapping key by sealing it into the machine's TPM
// through systemd-creds.
//
// Shelling out to systemd-creds rather than talking to the TPM directly is a
// deliberate trade: it keeps SYNSEC free of a TPM stack, and systemd already
// handles PCR policy, fallbacks and the host key file correctly.
type SystemdTPM2 struct{}

func (SystemdTPM2) Name() string { return "systemd-tpm2" }

func (SystemdTPM2) Protection() Protection {
	return Protection{
		ResistsDiskTheft: true,
		Summary:          "La clé est scellée dans la puce TPM de la machine. Un disque volé est inexploitable.",
		Caveat:           "La clé ne quitte jamais cette machine : en cas de panne matérielle, la restauration passe obligatoirement par le code de récupération imprimé.",
	}
}

func (SystemdTPM2) Protect(key []byte) ([]byte, error) {
	return runSystemdCreds(key, "encrypt", "--name="+credentialName, "--with-key=tpm2", "-", "-")
}

func (SystemdTPM2) Expose(handle []byte) ([]byte, error) {
	if len(handle) == 0 {
		return nil, ErrNoHandle
	}
	return runSystemdCreds(handle, "decrypt", "--name="+credentialName, "-", "-")
}

func runSystemdCreds(stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), systemdTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "systemd-creds", args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("unseal: systemd-creds %s timed out after %s", args[0], systemdTimeout)
		}
		return nil, fmt.Errorf("unseal: systemd-creds %s: %w: %s", args[0], err, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

// systemdTPM2Available reports whether this host can seal to a TPM.
func systemdTPM2Available() bool {
	if _, err := exec.LookPath("systemd-creds"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), systemdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "systemd-creds", "has-tpm2").Run() == nil
}

// TPM2Missing explique pourquoi la puce n'est pas utilisable, quand elle ne
// l'est pas.
//
// « systemd-creds has-tpm2 » répond bien plus qu'un oui ou un non : il détaille
// séparément le firmware, le pilote, le noyau et les bibliothèques, et sort
// avec un code non nul dès qu'une seule pièce manque. Ne regarder que ce code
// revient à confondre « cette machine n'a pas de puce » avec « il manque un
// paquet » - deux situations qui n'appellent pas du tout le même geste.
//
// Écrit après avoir vu SYNSEC annoncer « aucune puce TPM utilisable sur cette
// machine » sur un serveur Ubuntu qui en avait une, pilote chargé et
// /dev/tpmrm0 en place, où il ne manquait qu'un paquet. Le conseil d'aller
// fouiller le firmware envoyait alors chercher ce qui était déjà là.
//
// Renvoie une chaîne vide quand la puce est utilisable, quand il n'y en a
// simplement pas, ou quand rien ne permet de conclure : l'appelant donne
// alors son conseil habituel.
func TPM2Missing() string {
	out, err := exec.Command("systemd-creds", "has-tpm2").Output()
	if err == nil {
		return ""
	}
	return expliqueHasTPM2(string(out))
}

// expliqueHasTPM2 traduit le rapport de has-tpm2 en un geste à faire.
//
// Séparé de l'appel système pour être vérifiable sans puce : c'est justement
// sur les machines qui n'en ont pas que ce texte compte.
func expliqueHasTPM2(rapport string) string {
	var firmware, pilote, noyau, bibliotheques bool
	for _, ligne := range strings.Split(rapport, "\n") {
		switch strings.TrimSpace(ligne) {
		case "-firmware":
			firmware = true
		case "-driver":
			pilote = true
		case "-system", "-subsystem":
			noyau = true
		case "-libraries":
			bibliotheques = true
		}
	}

	switch {
	case firmware:
		// Vraiment pas de puce. Le conseil générique - en ajouter une - est
		// le bon, et le répéter ici ne ferait que le dédoubler.
		return ""
	case pilote || noyau:
		return "La puce existe mais le système ne l'atteint pas : le pilote " +
			"TPM n'est pas chargé. Regarde « ls /dev/tpmrm0 » et le module " +
			"tpm_tis, puis « systemd-creds has-tpm2 »."
	case bibliotheques:
		return "La puce est présente et son pilote est chargé : il ne manque " +
			"que les bibliothèques TPM2. Sur Debian et Ubuntu, « sudo apt " +
			"install libtss2-rc0t64 ». Ensuite « synsec maintenance sceller » " +
			"déplace la clé dans la puce sans rien réinstaller."
	}
	return ""
}
