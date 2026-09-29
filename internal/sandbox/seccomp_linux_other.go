//go:build linux && !amd64 && !arm64

package sandbox

// The list of system calls is kept for amd64 and arm64, the machines
// BoundGate is released for.
func seccomp(Mode) (int, error) { return 0, errNoSeccomp }
