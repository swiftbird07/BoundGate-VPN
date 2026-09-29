package sandbox

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	// from here on the numbers are x32's: the same machine, other calls
	numberLimit = 0x40000000
)

// arch_prctl: every new thread of the runtime sets its thread-local
// storage with it.
var archOnly = []uint32{unix.SYS_NEWFSTATAT, unix.SYS_ARCH_PRCTL}
