//go:build linux && (amd64 || arm64)

package sandbox

import "golang.org/x/sys/unix"

// What a Go network daemon without cgo asks of the kernel: the runtime
// (threads, memory, timers, signals, the network poller), sockets, and
// files in its own directories. The list was read from the runtime's and
// the libraries' sources and then run against the lab in audit mode
// (deploy/compose/e2e.sh); what is called most comes first, since the
// filter is read from the top at every call.
//
// Not on it, among much else: execve, fork, ptrace, mount, setuid, bpf,
// io_uring, keyctl, perf_event_open, userfaultfd, unshare, setns, chroot,
// the module calls, every timer and profiling call the node does not use.
var common = []uint32{
	unix.SYS_FUTEX, unix.SYS_READ, unix.SYS_WRITE, unix.SYS_EPOLL_PWAIT, unix.SYS_NANOSLEEP,
	unix.SYS_RECVMSG, unix.SYS_SENDMSG, unix.SYS_RECVMMSG, unix.SYS_SENDMMSG, unix.SYS_RECVFROM, unix.SYS_SENDTO,
	unix.SYS_SCHED_YIELD, unix.SYS_CLOCK_GETTIME, unix.SYS_GETPID, unix.SYS_GETTID,
	unix.SYS_MADVISE, unix.SYS_MUNMAP, unix.SYS_BRK, unix.SYS_MINCORE,
	unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGACTION, unix.SYS_SIGALTSTACK,
	unix.SYS_EPOLL_PWAIT2, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_CREATE1, unix.SYS_EVENTFD2, unix.SYS_PIPE2,
	unix.SYS_CLOSE, unix.SYS_OPENAT, unix.SYS_FSTAT, unix.SYS_STATX, unix.SYS_LSEEK,
	unix.SYS_PREAD64, unix.SYS_PWRITE64, unix.SYS_READV, unix.SYS_WRITEV,
	unix.SYS_FCNTL, unix.SYS_FSYNC, unix.SYS_FDATASYNC, unix.SYS_FTRUNCATE,
	unix.SYS_GETDENTS64, unix.SYS_GETCWD, unix.SYS_READLINKAT, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2,
	unix.SYS_MKDIRAT, unix.SYS_UNLINKAT, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2, unix.SYS_FCHMOD, unix.SYS_FCHMODAT,
	unix.SYS_DUP, unix.SYS_DUP3,
	unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT4, unix.SYS_SHUTDOWN,
	unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_SETSOCKOPT, unix.SYS_GETSOCKOPT,
	unix.SYS_GETRANDOM, unix.SYS_UNAME, unix.SYS_SCHED_GETAFFINITY,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID,
	unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_RESTART_SYSCALL,
}

// What ends the process wherever it is tried: the node starts no program
// and looks into no other process, so whoever asks is not the node.
var deadly = []uint32{
	unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
}

// table is the filter's content for this machine and this process.
func table(pid int) rules {
	return rules{
		arch:  auditArch,
		limit: numberLimit,
		pid:   uint32(pid),
		kill:  deadly,
		allow: append(append([]uint32{}, common...), archOnly...),

		clone:  unix.SYS_CLONE,
		socket: unix.SYS_SOCKET,
		ioctl:  unix.SYS_IOCTL,
		prctl:  unix.SYS_PRCTL,
		signal: []uint32{unix.SYS_TGKILL, unix.SYS_KILL},
		noExec: []uint32{unix.SYS_MMAP, unix.SYS_MPROTECT},

		unix:      unix.AF_UNIX,
		inet:      []uint32{unix.AF_INET, unix.AF_INET6},
		protocols: []uint32{0, unix.IPPROTO_TCP, unix.IPPROTO_UDP},
		netlink:   unix.AF_NETLINK,
		// the tunnel device the parent passed (its name, its offloads) and
		// what an interface's index and MTU are; nothing that changes the
		// machine
		requests: []uint32{unix.TUNGETIFF, unix.TUNSETOFFLOAD, unix.SIOCGIFMTU, unix.SIOCGIFINDEX},
		// the runtime names its memory regions (PR_SET_VMA)
		options: []uint32{unix.PR_SET_VMA},
	}
}
