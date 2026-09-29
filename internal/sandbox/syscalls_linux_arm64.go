package sandbox

import "golang.org/x/sys/unix"

const (
	auditArch   = unix.AUDIT_ARCH_AARCH64
	numberLimit = 0
)

var archOnly = []uint32{unix.SYS_FSTATAT}
