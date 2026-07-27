//go:build linux

package unseal

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
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
