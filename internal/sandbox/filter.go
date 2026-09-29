package sandbox

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// The filter as the kernel's seccomp sees a system call (struct
// seccomp_data): the number, the architecture, the arguments as 64-bit
// values. On the little-endian machines this is built for, an argument's
// low half comes first.
const (
	offNr   = 0
	offArch = 4
	offArgs = 16
)

func argLow(i int) uint32 { return uint32(offArgs + 8*i) }

// What a filter answers (SECCOMP_RET_*).
const (
	retKill  = 0x80000000 // the whole process
	retErrno = 0x00050000 // | errno
	retLog   = 0x7ffc0000
	retAllow = 0x7fff0000
)

// rules is the filter's content for one architecture and one process.
type rules struct {
	// arch is the AUDIT_ARCH_* value every call must carry: another one is
	// the machine's second instruction set (32-bit), whose numbers mean
	// other calls.
	arch uint32
	// limit > 0: numbers from limit on end the process (x32 on amd64).
	limit uint32
	// pid is the process itself, the only one it may signal.
	pid uint32

	kill  []uint32 // end the process, in every mode
	allow []uint32 // let through as they are

	// with a look at their arguments
	clone  uint32   // threads only
	socket uint32   // the address families below
	ioctl  uint32   // the requests below
	prctl  uint32   // the options below
	signal []uint32 // kill, tgkill: to itself only
	noExec []uint32 // mmap, mprotect: never executable memory

	unix      uint32   // the family of unix sockets
	inet      []uint32 // the families of the internet, with the protocols below
	protocols []uint32
	netlink   uint32 // the family that is let through with protocol 0 (NETLINK_ROUTE)
	requests  []uint32
	options   []uint32
}

const (
	cloneThread = 0x00010000
	protExec    = 0x4

	errEPERM           = 1
	errENOTTY          = 25
	errENOSYS          = 38
	errEPROTONOSUPPORT = 93
	errEAFNOSUPPORT    = 97
)

// assemble writes the filter. audit lets through what enforce refuses, and
// has the kernel log it; what ends the process ends it in both.
func (r rules) assemble(audit bool) []bpf.Instruction {
	refuse := func(errno uint32) bpf.Instruction {
		if audit {
			return bpf.RetConstant{Val: retLog}
		}
		return bpf.RetConstant{Val: retErrno | errno}
	}
	// memory that is writable and then executable is how injected code
	// runs: nothing in a Go program without cgo asks for it
	exec := bpf.Instruction(bpf.RetConstant{Val: retKill})
	if audit {
		exec = bpf.RetConstant{Val: retLog}
	}
	is := func(nr uint32, block ...bpf.Instruction) []bpf.Instruction {
		// every block ends in a return on each of its paths, so the
		// accumulator still holds the number where the next test reads it
		return append([]bpf.Instruction{bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: uint8(len(block))}}, block...)
	}
	oneOf := func(off uint32, vals []uint32, no bpf.Instruction) []bpf.Instruction {
		b := []bpf.Instruction{bpf.LoadAbsolute{Off: off, Size: 4}}
		for i, v := range vals {
			b = append(b, bpf.JumpIf{Cond: bpf.JumpEqual, Val: v, SkipTrue: uint8(len(vals) - i)})
		}
		return append(b, no, bpf.RetConstant{Val: retAllow})
	}

	p := []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArch, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: r.arch, SkipTrue: 1},
		bpf.RetConstant{Val: retKill},
		bpf.LoadAbsolute{Off: offNr, Size: 4},
	}
	if r.limit > 0 {
		p = append(p,
			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: r.limit, SkipFalse: 1},
			bpf.RetConstant{Val: retKill})
	}
	for _, nr := range r.kill {
		p = append(p, is(nr, bpf.RetConstant{Val: retKill})...)
	}
	for _, nr := range r.noExec {
		// both take the protection as their third argument
		p = append(p, is(nr,
			bpf.LoadAbsolute{Off: argLow(2), Size: 4},
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: protExec, SkipFalse: 1},
			exec,
			bpf.RetConstant{Val: retAllow})...)
	}
	for _, nr := range r.allow {
		p = append(p, is(nr, bpf.RetConstant{Val: retAllow})...)
	}
	p = append(p, is(r.clone,
		bpf.LoadAbsolute{Off: argLow(0), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: cloneThread, SkipTrue: 1},
		refuse(errEPERM),
		bpf.RetConstant{Val: retAllow})...)
	for _, nr := range r.signal {
		p = append(p, is(nr, oneOf(argLow(0), []uint32{r.pid}, refuse(errEPERM))...)...)
	}
	// socket(family, type, protocol): unix sockets, TCP and UDP, and of
	// netlink only the routing protocol (what the machine's networks are:
	// read-only without privileges). Not MPTCP: Landlock's rule about
	// listening is about TCP sockets, and Go would listen with MPTCP where
	// the kernel has it; told that it has none, Go takes TCP.
	sock := []bpf.Instruction{bpf.LoadAbsolute{Off: argLow(0), Size: 4}}
	sock = append(sock, is(r.unix, bpf.RetConstant{Val: retAllow})...)
	for _, f := range r.inet {
		sock = append(sock, is(f, oneOf(argLow(2), r.protocols, refuse(errEPROTONOSUPPORT))...)...)
	}
	sock = append(sock, is(r.netlink, oneOf(argLow(2), []uint32{0}, refuse(errEAFNOSUPPORT))...)...)
	sock = append(sock, refuse(errEAFNOSUPPORT))
	p = append(p, is(r.socket, sock...)...)
	p = append(p, is(r.ioctl, oneOf(argLow(1), r.requests, refuse(errENOTTY))...)...)
	p = append(p, is(r.prctl, oneOf(argLow(0), r.options, refuse(errEPERM))...)...)
	return append(p, refuse(errENOSYS))
}

// check: a jump in a filter reaches 255 instructions far; the lists with a
// look at the arguments are jumped over in one.
func (r rules) check() error {
	for _, n := range []int{len(r.protocols), len(r.requests), len(r.options)} {
		if n > 200 {
			return fmt.Errorf("sandbox: a list of %d arguments is too long for one jump", n)
		}
	}
	return nil
}

// count is the number of system calls the filter lets through at all.
func (r rules) count() int {
	return len(r.allow) + len(r.noExec) + len(r.signal) + 4
}
