// Package sandbox confines a process that reads bytes others chose: the
// worker of privilege separation (docs/PRIVSEP.md). Two mechanisms of the
// Linux kernel, both set by the process on itself and neither to be taken
// back: a seccomp filter (which system calls, and with which arguments) and
// a Landlock domain (which files, which TCP ports to listen on).
//
// What it is for: code execution in the worker should find no way out of
// it. No other program can be started, no memory made executable, no file
// read or written outside the node's own directories, and the kernel is
// reached only through the system calls a Go network daemon needs.
package sandbox

import (
	"fmt"
	"strings"
)

// Mode is how much of the sandbox applies.
type Mode string

const (
	// Enforce: what the rules do not allow fails (or ends the process).
	Enforce Mode = "enforce"
	// Audit: system calls off the list are allowed and written to the
	// kernel's log (audit type 1326), to find what a new kernel or Go
	// release needs before it is refused. Starting a program, reading
	// another process's memory and the file rules stay enforced.
	Audit Mode = "audit"
	// Off: no sandbox.
	Off Mode = "off"
)

// ParseMode reads the configured mode; empty is Enforce.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", Enforce:
		return Enforce, nil
	case Audit:
		return Audit, nil
	case Off:
		return Off, nil
	}
	return "", fmt.Errorf("sandbox: mode %q is none of enforce, audit, off", s)
}

// Policy is what the process keeps.
type Policy struct {
	Mode Mode
	// ReadWrite are the directories the process owns: its state, its logs.
	ReadWrite []string
	// ReadOnly are files and directories it reads: resolver configuration,
	// CA roots, time zones. What does not exist is left out.
	ReadOnly []string
	// BindTCP are the TCP ports it may listen on; none means no TCP
	// listener at all. (UDP is not something Landlock decides.)
	BindTCP []uint16
}

// Report is what was applied.
type Report struct {
	// Seccomp is the filter's mode ("enforce", "audit"), empty without one.
	Seccomp string
	// Syscalls is the number of system calls the filter lets through.
	Syscalls int
	// Landlock is the ABI version of the kernel that the domain was built
	// for, 0 without a domain.
	Landlock int
	// Missing says why a part is not there.
	Missing []string
}

func (r Report) String() string {
	var parts []string
	if r.Seccomp != "" {
		s := fmt.Sprintf("seccomp (%d system calls", r.Syscalls)
		if r.Seccomp != string(Enforce) {
			s += ", " + r.Seccomp + " only"
		}
		parts = append(parts, s+")")
	}
	if r.Landlock > 0 {
		parts = append(parts, fmt.Sprintf("landlock v%d", r.Landlock))
	}
	if len(parts) == 0 {
		parts = append(parts, "none")
	}
	s := strings.Join(parts, ", ")
	if len(r.Missing) > 0 {
		s += "; " + strings.Join(r.Missing, "; ")
	}
	return s
}
