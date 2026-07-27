//go:build windows

package unseal

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// DPAPI is bound by hand rather than through golang.org/x/sys/windows: these
// two entry points are stable, and the direct binding keeps the dependency
// surface of the unseal path - the most security-sensitive code in SYNSEC -
// down to the standard library.
var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")

	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree = kernel32.NewProc("LocalFree")
)

const (
	// cryptprotectUIForbidden makes DPAPI fail outright rather than attempt to
	// prompt. SYNSEC runs as a service and has no desktop to draw a dialog on;
	// a silent failure to start beats a hung service waiting on an invisible
	// prompt.
	cryptprotectUIForbidden = 0x1

	// cryptprotectLocalMachine ties the sealed key to the machine rather than
	// to one account.
	//
	// Account scope is stronger and was the first choice, but a Windows
	// service runs as LocalSystem: a key sealed by whoever ran `synsec init`
	// would be unreadable by the service, which would fail to unseal at every
	// boot and restart in a loop. Since unattended start is the whole point,
	// machine scope is the coherent trade - and the scenario that actually
	// matters for a home server, someone walking off with the disk or a
	// backup, stays covered either way.
	cryptprotectLocalMachine = 0x4
)

// dpapiEntropy is mixed into every operation so that a blob produced by some
// other application running under the same account cannot be substituted for
// ours.
var dpapiEntropy = []byte("synsec/dpapi/v1")

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// bytes copies the payload out of the buffer DPAPI allocated on our behalf.
func (b *dataBlob) bytes() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func (b *dataBlob) free() {
	if b.pbData != nil {
		procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
		b.pbData = nil
	}
}

// DPAPI protects the wrapping key with the Windows Data Protection API, tied
// to the machine.
type DPAPI struct{}

func (DPAPI) Name() string { return "dpapi" }

func (DPAPI) Protection() Protection {
	return Protection{
		ResistsDiskTheft: true,
		Summary:          "La clé est protégée par Windows et liée à cette machine. Un disque volé, ou une sauvegarde emportée ailleurs, est inexploitable.",
		Caveat:           "Sur cette machine, un compte administrateur peut déchiffrer la clé : c'est ce qui permet au service de démarrer tout seul. Et si Windows est réinstallé, seul le code de récupération imprimé rouvrira le coffre.",
	}
}

func (DPAPI) Protect(key []byte) ([]byte, error) {
	in, entropy := newBlob(key), newBlob(dpapiEntropy)
	var out dataBlob

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, // szDataDescr
		uintptr(unsafe.Pointer(entropy)),
		0, // pvReserved
		0, // pPromptStruct
		cryptprotectUIForbidden|cryptprotectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(dpapiEntropy)
	if ret == 0 {
		return nil, fmt.Errorf("unseal: CryptProtectData: %w", err)
	}
	defer out.free()
	return out.bytes(), nil
}

func (DPAPI) Expose(handle []byte) ([]byte, error) {
	if len(handle) == 0 {
		return nil, ErrNoHandle
	}
	in, entropy := newBlob(handle), newBlob(dpapiEntropy)
	var out dataBlob

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, // ppszDataDescr
		uintptr(unsafe.Pointer(entropy)),
		0, // pvReserved
		0, // pPromptStruct
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(handle)
	runtime.KeepAlive(dpapiEntropy)
	if ret == 0 {
		return nil, fmt.Errorf("unseal: CryptUnprotectData: %w", err)
	}
	defer out.free()
	return out.bytes(), nil
}
