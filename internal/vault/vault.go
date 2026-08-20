// Package vault joins the cryptography to the database.
//
// It owns the root key: nothing else in SYNSEC ever holds it. The server
// starts sealed, unseals itself from the host keystore, and from then on hands
// out decrypted values without any other component needing to know a key
// exists at all.
package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"synsec/internal/crypto"
	"synsec/internal/store"
	"synsec/internal/unseal"
)

// Identifiers of the two slots created during setup, and the meta key
// recording which unseal provider was chosen.
const (
	slotIDMachine      = "machine"
	slotIDRecovery     = "recovery"
	metaUnsealProvider = "unseal.provider"
)

var (
	// ErrSealed means the root key is not in memory. Every read and write
	// fails with it until the server is unsealed.
	ErrSealed = errors.New("vault: server is sealed")

	// ErrAlreadyInitialized guards against a second setup run, which would
	// generate a new root key and strand every existing secret.
	ErrAlreadyInitialized = errors.New("vault: already initialised")

	// ErrBadRecoveryCode means the code does not open the recovery slot.
	ErrBadRecoveryCode = errors.New("vault: recovery code is not valid")
)

// Manager holds the root key and mediates every access to secret material.
type Manager struct {
	db  *store.DB
	dir string

	mu   sync.RWMutex
	root *crypto.Key // nil while sealed
}

// New builds a manager over an already-open database. dataDir is where a
// keyfile provider would put its key.
func New(db *store.DB, dataDir string) *Manager {
	return &Manager{db: db, dir: dataDir}
}

// DB exposes the underlying store for the operations that need no key:
// listing vaults, reading the audit log, managing users.
func (m *Manager) DB() *store.DB { return m.db }

// InitResult reports what setup produced. RecoveryCode is shown exactly once,
// and Protection is what the wizard displays so the owner learns the real
// strength of their installation rather than a reassuring generality.
type InitResult struct {
	RecoveryCode string
	Provider     string
	Protection   unseal.Protection
}

// Initialized reports whether setup has already run.
func (m *Manager) Initialized(ctx context.Context) (bool, error) {
	n, err := m.db.CountKeySlots(ctx)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Initialize creates the root key and the two slots that open it: one bound to
// this host so the server can start unattended, one bound to a printed code so
// a dead machine is not a dead archive.
//
// The manager is left unsealed on success.
func (m *Manager) Initialize(ctx context.Context) (InitResult, error) {
	done, err := m.Initialized(ctx)
	if err != nil {
		return InitResult{}, err
	}
	if done {
		return InitResult{}, ErrAlreadyInitialized
	}

	root, err := crypto.NewRandomKey()
	if err != nil {
		return InitResult{}, err
	}
	// The root key survives this function only if every step succeeds;
	// otherwise it must not linger in memory.
	committed := false
	defer func() {
		if !committed {
			root.Zero()
		}
	}()

	provider, err := m.provisionMachineSlot(ctx, root)
	if err != nil {
		return InitResult{}, err
	}

	code, err := NewRecoveryCode()
	if err != nil {
		return InitResult{}, err
	}
	recovery, err := crypto.NewSecretSlot(
		slotIDRecovery, crypto.SlotRecovery, root,
		[]byte(NormalizeRecoveryCode(code)), crypto.DefaultArgon2,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf("vault: building recovery slot: %w", err)
	}
	if err := m.db.SaveKeySlot(ctx, store.KeySlotRecord{Slot: *recovery}); err != nil {
		return InitResult{}, err
	}

	if err := m.db.SetMeta(ctx, metaUnsealProvider, []byte(provider.Name())); err != nil {
		return InitResult{}, err
	}

	m.setRoot(root)
	committed = true

	return InitResult{
		RecoveryCode: code,
		Provider:     provider.Name(),
		Protection:   provider.Protection(),
	}, nil
}

// provisionMachineSlot seals the root key to this host, falling back to the
// platform's second choice if the preferred keystore refuses.
//
// A failure here would otherwise abort setup entirely and leave a
// non-technical owner with an error message about DPAPI, so the fallback keeps
// the installation working - while Protection tells them exactly what they
// ended up with.
func (m *Manager) provisionMachineSlot(ctx context.Context, root *crypto.Key) (unseal.Provider, error) {
	preferred := unseal.Detect(m.dir)
	err := m.storeMachineSlot(ctx, preferred, root)
	if err == nil {
		return preferred, m.db.SetMeta(ctx, metaUnsealProvider, []byte(preferred.Name()))
	}

	fallback := unseal.Fallback(m.dir)
	if fallback.Name() == preferred.Name() {
		return nil, fmt.Errorf("vault: sealing to %s: %w", preferred.Name(), err)
	}
	if err2 := m.storeMachineSlot(ctx, fallback, root); err2 != nil {
		return nil, fmt.Errorf("vault: sealing to %s failed (%v) and to %s: %w",
			preferred.Name(), err, fallback.Name(), err2)
	}
	return fallback, m.db.SetMeta(ctx, metaUnsealProvider, []byte(fallback.Name()))
}

// CurrentProvider says what is protecting the key right now.
//
// Read from the slot rather than from the meta: the slot is what Unseal
// actually consults, so it is the only answer that cannot be stale.
func (m *Manager) CurrentProvider(ctx context.Context) (string, error) {
	rec, err := m.db.KeySlotByKind(ctx, crypto.SlotMachine)
	if err != nil {
		return "", err
	}
	return rec.Provider, nil
}

// BestProvider is what this host could use today, which is not necessarily
// what it uses: a machine that gained a TPM since its installation keeps the
// protection it was set up with until somebody asks for the change.
func (m *Manager) BestProvider() unseal.Provider { return unseal.Detect(m.dir) }

func (m *Manager) storeMachineSlot(ctx context.Context, provider unseal.Provider, root *crypto.Key) error {
	wrapping, err := crypto.NewRandomKey()
	if err != nil {
		return err
	}
	defer wrapping.Zero()

	handle, err := provider.Protect(wrapping.Bytes())
	if err != nil {
		return err
	}
	slot, err := crypto.NewMachineSlot(slotIDMachine, root, wrapping)
	if err != nil {
		return err
	}
	return m.db.SaveKeySlot(ctx, store.KeySlotRecord{
		Slot:     *slot,
		Provider: provider.Name(),
		Handle:   handle,
	})
}

// Unseal recovers the root key from the host keystore. This is what runs at
// every boot, with nobody watching.
func (m *Manager) Unseal(ctx context.Context) error {
	rec, err := m.db.KeySlotByKind(ctx, crypto.SlotMachine)
	if err != nil {
		return err
	}

	provider, err := unseal.ByName(rec.Provider, m.dir)
	if err != nil {
		return err
	}
	raw, err := provider.Expose(rec.Handle)
	if err != nil {
		return fmt.Errorf("vault: recovering key material from %s: %w", rec.Provider, err)
	}
	wrapping, err := crypto.KeyFrom(raw)
	if err != nil {
		return err
	}
	defer wrapping.Zero()

	root, err := rec.Slot.UnsealWith(wrapping)
	if err != nil {
		return fmt.Errorf("vault: machine slot did not open: %w", err)
	}
	m.setRoot(root)
	return nil
}

// UnsealWithRecovery opens the server with the printed code, for when the host
// keystore is gone: a reinstalled system, a changed service account, a new
// machine restored from backup.
func (m *Manager) UnsealWithRecovery(ctx context.Context, code string) error {
	if !validRecoveryCode(code) {
		return ErrBadRecoveryCode
	}
	rec, err := m.db.KeySlotByKind(ctx, crypto.SlotRecovery)
	if err != nil {
		return err
	}

	root, err := rec.Slot.Unseal([]byte(NormalizeRecoveryCode(code)))
	if err != nil {
		return ErrBadRecoveryCode
	}
	m.setRoot(root)
	return nil
}

// CheckRecoveryCode reports whether code opens the recovery slot, without
// leaving the server unsealed.
//
// It exists so that a command can demand proof that the caller holds the
// printed kit, rather than merely proof that they can reach the data
// directory. The root key is recovered and discarded immediately: possession
// is what is being tested, not access.
func (m *Manager) CheckRecoveryCode(ctx context.Context, code string) error {
	if !validRecoveryCode(code) {
		return ErrBadRecoveryCode
	}

	rec, err := m.db.KeySlotByKind(ctx, crypto.SlotRecovery)
	if err != nil {
		return err
	}

	root, err := rec.Slot.Unseal([]byte(NormalizeRecoveryCode(code)))
	if err != nil {
		return ErrBadRecoveryCode
	}
	root.Zero()
	return nil
}

// ReprovisionMachineSlot re-seals the root key to this host's keystore,
// completing a recovery: without it the server would need the printed code at
// every single boot.
func (m *Manager) ReprovisionMachineSlot(ctx context.Context) (unseal.Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.root == nil || m.root.Zeroed() {
		return nil, ErrSealed
	}
	return m.provisionMachineSlot(ctx, m.root)
}

// Seal wipes the root key from memory. Reads and writes fail until Unseal.
func (m *Manager) Seal() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.root != nil {
		m.root.Zero()
		m.root = nil
	}
}

// Sealed reports whether the root key is absent.
func (m *Manager) Sealed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.root == nil || m.root.Zeroed()
}

func (m *Manager) setRoot(root *crypto.Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.root != nil {
		m.root.Zero()
	}
	m.root = root
}

// withRoot runs fn with the root key held under a read lock, so a concurrent
// Seal cannot pull it out from underneath.
func (m *Manager) withRoot(fn func(root *crypto.Key) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.root == nil || m.root.Zeroed() {
		return ErrSealed
	}
	return fn(m.root)
}
