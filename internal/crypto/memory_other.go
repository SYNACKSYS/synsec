//go:build !linux && !windows

package crypto

// totalMemory has no answer on the platforms SYNSEC does not target.
//
// Saying so plainly is what makes the caller keep the default cost: guessing
// a number here would silently weaken password hashing on a machine nobody
// has measured.
func totalMemory() (uint64, bool) { return 0, false }
