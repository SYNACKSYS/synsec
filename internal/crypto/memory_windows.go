//go:build windows

package crypto

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// memoryStatusEx mirrors MEMORYSTATUSEX. Only TotalPhys is read, but the whole
// structure has to be there: the call writes all of it.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// totalMemory reports the machine's physical memory in bytes.
//
// golang.org/x/sys/windows does not wrap this call, and the project already
// reaches kernel32 this way for DPAPI, so it is the familiar shape here.
func totalMemory() (uint64, bool) {
	var status memoryStatusEx
	// The call reads Length to know which version of the structure it was
	// handed. Left at zero it fails instead of filling anything in.
	status.Length = uint32(unsafe.Sizeof(status))

	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if ret == 0 {
		return 0, false
	}
	return status.TotalPhys, true
}
