//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock's rights over files, by the ABI version that brought them.
const (
	fsV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM

	// what the process does in its own directories: plain files and
	// directories, nothing executed, no devices, sockets or links
	ownDir = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	readDir  = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	readFile = unix.LANDLOCK_ACCESS_FS_READ_FILE

	ruleNetPort = 2 // LANDLOCK_RULE_NET_PORT
)

// struct landlock_net_port_attr
type netPortAttr struct {
	allowed uint64
	port    uint64
}

// errNoLandlock: this kernel has none, or it is not switched on, or what
// runs the container does not let the calls through.
var errNoLandlock = errors.New("the kernel offers no Landlock (Linux 5.13 and the landlock security module)")

// landlock builds the domain and puts every thread into it. It returns the
// ABI version it was built for.
func landlock(p Policy) (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	switch {
	case errno == unix.ENOSYS || errno == unix.EOPNOTSUPP || errno == unix.EPERM:
		return 0, errNoLandlock
	case errno != 0:
		return 0, fmt.Errorf("sandbox: landlock: %w", errno)
	case v < 1:
		return 0, errNoLandlock
	}
	abi := int(v)
	attr := unix.LandlockRulesetAttr{Access_fs: fsV1}
	if abi >= 2 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 4 {
		// listening only: where the node connects to (hubs, the control
		// plane) is not known before the control plane says it
		attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP
	}
	if abi >= 5 {
		// device files opened from here on take no ioctl; the tunnel
		// device was opened by the parent
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	if abi >= 6 {
		// no connection to abstract unix sockets of others. Signals are
		// the seccomp filter's: Landlock's scope counts the threads of a
		// Go program as strangers to each other on kernels before 6.15
		attr.Scoped = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return 0, fmt.Errorf("sandbox: landlock ruleset: %w", errno)
	}
	ruleset := int(fd)
	defer unix.Close(ruleset)

	for _, dir := range p.ReadWrite {
		if err := allowPath(ruleset, dir, ownDir&attr.Access_fs, true); err != nil {
			return 0, err
		}
	}
	for _, path := range p.ReadOnly {
		if err := allowPath(ruleset, path, readDir, false); err != nil {
			return 0, err
		}
	}
	if abi >= 4 {
		for _, port := range p.BindTCP {
			rule := netPortAttr{allowed: unix.LANDLOCK_ACCESS_NET_BIND_TCP, port: uint64(port)}
			if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), ruleNetPort, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
				return 0, fmt.Errorf("sandbox: landlock: port %d: %w", port, errno)
			}
		}
	}

	// Every thread enters the domain, not only this one: a Go program's
	// code runs on whichever thread is free. (Without cgo; with it Go
	// cannot reach every thread and says so.)
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return 0, fmt.Errorf("sandbox: no_new_privs on every thread: %w", errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return 0, fmt.Errorf("sandbox: landlock: enter the domain: %w", errno)
	}
	return abi, nil
}

// allowPath adds what is beneath path. must: a path that is not there is
// an error (the process's own directories), else it is left out.
func allowPath(ruleset int, path string, access uint64, must bool) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if !must && (errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, unix.ENOTDIR)) {
			return nil
		}
		return fmt.Errorf("sandbox: landlock: %s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("sandbox: landlock: %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if must {
			return fmt.Errorf("sandbox: landlock: %s is not a directory", path)
		}
		access &= readFile
	}
	rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("sandbox: landlock: %s: %w", path, errno)
	}
	return nil
}
