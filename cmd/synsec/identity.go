package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"synsec/internal/auth"
	"synsec/internal/crypto"
	"synsec/internal/store"
)

// EnvUser names the account to act as, so an interactive session does not have
// to repeat -user on every command.
const EnvUser = "SYNSEC_USER"

// identityFlag registers the option shared by every command that touches a
// secret.
func identityFlag(fs *flag.FlagSet) *string {
	return fs.String("user", "", "compte SYNSEC (ou variable "+EnvUser+")")
}

// authenticate identifies the person running the command.
//
// The command line has no session, so it asks. Deliberately the same accounts
// and the same password verifier as the web interface: one identity model, one
// set of rules to keep in step, and an audit trail that names a person instead
// of recording "cli".
//
// This does not make the command line a boundary. The root key is sealed to
// the machine so the service can start unattended, which means any local
// administrator can decrypt the database without going through SYNSEC at all.
// What it buys is that reading someone else's secret takes a deliberate act
// and leaves a trace.
func authenticate(ctx context.Context, db *store.DB, username string) (store.User, error) {
	if username == "" {
		username = os.Getenv(EnvUser)
	}
	if username == "" {
		return store.User{}, fmt.Errorf("indique le compte à utiliser :\n"+
			"          synsec ... -user <nom>\n"+
			"        ou pose la variable %s une fois pour la session", EnvUser)
	}

	user, err := db.UserByUsername(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	known := err == nil

	password, err := promptPassword("Mot de passe de « " + username + " » : ")
	if err != nil {
		return store.User{}, err
	}

	// An unknown account still costs a full password hash, so the time taken
	// cannot be used to find out which accounts exist.
	if !known {
		auth.VerifyPassword(decoyCredentials(), password)
		return store.User{}, errors.New("nom d'utilisateur ou mot de passe incorrect")
	}

	cred, err := db.UserCredentials(ctx, user.ID)
	if err != nil {
		return store.User{}, err
	}
	if !auth.VerifyPassword(cred, password) {
		return store.User{}, errors.New("nom d'utilisateur ou mot de passe incorrect")
	}
	return user, nil
}

// decoyCredentials is a well-formed verifier that nothing matches, used to
// spend the same time on an unknown account as on a real one.
func decoyCredentials() store.Credentials {
	return store.Credentials{
		Hash:   make([]byte, 32),
		Salt:   make([]byte, 16),
		Params: crypto.DefaultArgon2,
	}
}

// requireVaultRole checks that user holds at least the role needed on a vault.
//
// Unlike the web interface, which answers "not found" so that nobody can map
// what they cannot open, the command line says plainly what is missing: it is
// run by someone standing at the machine, and a puzzling refusal there costs
// time without buying anything.
func requireVaultRole(ctx context.Context, db *store.DB, user store.User, p store.Project, needed store.Role) error {
	role, err := db.VaultRole(ctx, p.ID, user.ID)
	if err != nil {
		return err
	}
	if !role.AtLeast(needed) {
		return fmt.Errorf("« %s » n'a pas l'accès en %s au coffre « %s » (accès actuel : %s)",
			user.Username, needed.Label(), p.Name, role.Label())
	}
	return nil
}

// requireSecretRole checks access to one secret, counting an individual share
// as well as membership of the vault.
func requireSecretRole(ctx context.Context, db *store.DB, user store.User, p store.Project, env, path string, needed store.Role) (store.Secret, error) {
	loc := store.SecretLocation{ProjectID: p.ID, Env: env, Name: path}

	secret, err := db.SecretMeta(ctx, loc)
	if errors.Is(err, store.ErrNotFound) {
		return store.Secret{}, fmt.Errorf("aucun secret nommé %s dans « %s »", path, p.Name)
	}
	if err != nil {
		return store.Secret{}, err
	}

	fromVault, err := db.VaultRole(ctx, p.ID, user.ID)
	if err != nil {
		return store.Secret{}, err
	}
	fromShare, err := db.SecretShareRole(ctx, secret.ID, user.ID)
	if err != nil {
		return store.Secret{}, err
	}

	// Access is additive: a share raises what the vault grants, never lowers it.
	if role := store.Higher(fromVault, fromShare); !role.AtLeast(needed) {
		return store.Secret{}, fmt.Errorf("« %s » n'a pas l'accès en %s à %s (accès actuel : %s)",
			user.Username, needed.Label(), path, role.Label())
	}
	return secret, nil
}

// auditCLI records what was done from the command line, naming the person and
// the vault it happened in.
func auditCLI(ctx context.Context, db *store.DB, user store.User, projectID, action, target string) {
	err := db.AppendAudit(ctx, store.AuditEntry{
		ActorKind:  store.ActorUser,
		ActorID:    user.ID,
		ActorLabel: user.Username,
		Action:     action,
		Target:     target,
		ProjectID:  projectID,
		Detail:     "ligne de commande",
	})
	if err != nil {
		// A lost log line must not fail an operation that otherwise worked.
		fmt.Fprintf(os.Stderr, "note : journal d'audit non écrit (%v)\n", err)
	}
}
