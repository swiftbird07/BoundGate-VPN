//go:build linux && (amd64 || arm64)

package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// seccomp puts the filter on every thread of the process at once (TSYNC);
// threads that come later inherit it. It returns the number of system
// calls the filter lets through.
func seccomp(mode Mode) (int, error) {
	t := table(os.Getpid())
	if err := t.check(); err != nil {
		return 0, err
	}
	raw, err := bpf.Assemble(t.assemble(mode == Audit))
	if err != nil {
		return 0, fmt.Errorf("sandbox: seccomp filter: %w", err)
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}

	// the kernel takes a filter from a thread that can gain no privileges
	// any more, and gives the others the same
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("sandbox: no_new_privs: %w", err)
	}
	// LOG: what the filter refuses is written to the kernel's log
	flags := uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_LOG)
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return 0, fmt.Errorf("sandbox: seccomp: %w", errno)
	}
	if r != 0 {
		return 0, fmt.Errorf("sandbox: seccomp: thread %d could not take the filter", r)
	}
	return t.count(), nil
}
