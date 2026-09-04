//go:build linux

package crypto

import (
	"os"
	"strconv"
	"strings"
)

// totalMemory reports the machine's physical memory in bytes.
//
// /proc/meminfo rather than a syscall: it is stable, it needs no cgo, and it
// is the same number every other tool on the machine reports.
func totalMemory() (uint64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, found := strings.CutPrefix(line, "MemTotal:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		kib, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return kib * 1024, true
	}
	return 0, false
}
