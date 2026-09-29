package sandbox

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

// call is a system call as the filter sees it. The test machine of
// x/net/bpf reads big-endian, the kernel's reads the machine's own order:
// each 32-bit half is written where the kernel has it, in the order the
// test machine reads.
func call(arch, nr uint32, args ...uint64) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b[offNr:], nr)
	binary.BigEndian.PutUint32(b[offArch:], arch)
	for i, a := range args {
		binary.BigEndian.PutUint32(b[offArgs+8*i:], uint32(a))
		binary.BigEndian.PutUint32(b[offArgs+8*i+4:], uint32(a>>32))
	}
	return b
}

var testRules = rules{
	arch: 0xc00000b7, limit: 0x40000000, pid: 4711,
	kill:  []uint32{221, 281},
	allow: []uint32{63, 64, 98},
	clone: 220, socket: 198, ioctl: 29, prctl: 167,
	signal: []uint32{131, 129},
	noExec: []uint32{222, 226},

	unix: 1, inet: []uint32{2, 10}, protocols: []uint32{0, 6, 17}, netlink: 16,
	requests: []uint32{0x800454d2, 0x8921},
	options:  []uint32{0x53564d41},
}

func TestTheFilterDecides(t *testing.T) {
	const arch = 0xc00000b7
	for _, tc := range []struct {
		name           string
		in             []byte
		enforce, audit uint32
	}{
		{"another instruction set", call(0x40000028, 63), retKill, retKill},
		{"a number past the limit", call(arch, 0x40000000+63), retKill, retKill},
		{"on the list", call(arch, 63), retAllow, retAllow},
		{"the last of the list", call(arch, 98), retAllow, retAllow},
		{"not on the list", call(arch, 280), retErrno | errENOSYS, retLog},
		{"execve", call(arch, 221), retKill, retKill},
		{"execveat", call(arch, 281), retKill, retKill},
		{"a thread", call(arch, 220, 0x50f00), retAllow, retAllow},
		{"a process", call(arch, 220, 0x11), retErrno | errEPERM, retLog},
		{"a signal to itself", call(arch, 129, 4711, 15), retAllow, retAllow},
		{"a signal to a thread of itself", call(arch, 131, 4711, 4712, 23), retAllow, retAllow},
		{"a signal to the parent", call(arch, 129, 1, 9), retErrno | errEPERM, retLog},
		{"a signal to its process group", call(arch, 129, 0, 9), retErrno | errEPERM, retLog},
		{"a signal to everyone", call(arch, 129, 0xffffffffffffffff, 9), retErrno | errEPERM, retLog},
		{"memory to read and write", call(arch, 222, 0, 4096, 3), retAllow, retAllow},
		{"memory to execute", call(arch, 222, 0, 4096, 7), retKill, retLog},
		{"memory made executable", call(arch, 226, 0x1000, 4096, 5), retKill, retLog},
		{"a UDP socket", call(arch, 198, 2, 2, 0), retAllow, retAllow},
		{"an IPv6 socket", call(arch, 198, 10, 1, 0), retAllow, retAllow},
		{"an IPv6 UDP socket, named", call(arch, 198, 10, 2, 17), retAllow, retAllow},
		{"an MPTCP socket", call(arch, 198, 2, 1, 262), retErrno | errEPROTONOSUPPORT, retLog},
		{"an SCTP socket", call(arch, 198, 10, 1, 132), retErrno | errEPROTONOSUPPORT, retLog},
		{"a unix socket with a protocol", call(arch, 198, 1, 1, 7), retAllow, retAllow},
		{"a unix socket", call(arch, 198, 1, 1, 0), retAllow, retAllow},
		{"a routing socket", call(arch, 198, 16, 3, 0), retAllow, retAllow},
		{"a netfilter socket", call(arch, 198, 16, 3, 12), retErrno | errEAFNOSUPPORT, retLog},
		{"a packet socket", call(arch, 198, 17, 3, 0x300), retErrno | errEAFNOSUPPORT, retLog},
		{"the tunnel's name", call(arch, 29, 5, 0x800454d2), retAllow, retAllow},
		{"an interface's MTU", call(arch, 29, 5, 0x8921), retAllow, retAllow},
		{"a new tunnel device", call(arch, 29, 5, 0x400454ca), retErrno | errENOTTY, retLog},
		{"a name for memory", call(arch, 167, 0x53564d41), retAllow, retAllow},
		{"dumpable", call(arch, 167, 4, 1), retErrno | errEPERM, retLog},
	} {
		for _, mode := range []struct {
			audit bool
			want  uint32
		}{{false, tc.enforce}, {true, tc.audit}} {
			vm, err := bpf.NewVM(testRules.assemble(mode.audit))
			if err != nil {
				t.Fatal(err)
			}
			got, err := vm.Run(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if uint32(got) != mode.want {
				t.Errorf("%s (audit %v): the filter answers %#x, not %#x", tc.name, mode.audit, got, mode.want)
			}
		}
	}
}

// The kernel takes filters of at most 4096 instructions with jumps of at
// most 255: a list that outgrows that must fail here, not at a node's start.
func TestTheFilterAssembles(t *testing.T) {
	raw, err := bpf.Assemble(testRules.assemble(false))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		t.Fatalf("%d instructions, %v", len(raw), err)
	}
	r := testRules
	r.requests = make([]uint32, 201)
	if r.check() == nil {
		t.Fatal("201 requests in one jump")
	}
}

func TestModes(t *testing.T) {
	for in, want := range map[string]Mode{"": Enforce, "enforce": Enforce, " Audit ": Audit, "off": Off} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := ParseMode("on"); err == nil {
		t.Error("an unknown mode was taken")
	}
	r := Report{Seccomp: "enforce", Syscalls: 80, Landlock: 4}
	if r.String() != "seccomp (80 system calls), landlock v4" {
		t.Error(r.String())
	}
	r = Report{Seccomp: "audit", Syscalls: 80, Missing: []string{"no landlock: old kernel"}}
	if r.String() != "seccomp (80 system calls, audit only); no landlock: old kernel" {
		t.Error(r.String())
	}
}
