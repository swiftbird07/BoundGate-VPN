//go:build linux

package sandbox

import "errors"

// errNoSeccomp: no list of system calls for this machine.
var errNoSeccomp = errors.New("no filter for this architecture (amd64 and arm64 have one)")

// Apply confines this process, for good. Landlock first, then the seccomp
// filter, which no longer lets the calls through that built the first.
//
// A kernel without Landlock and a machine without a filter are reported,
// not errors: the other part still applies. A part that is there and
// cannot be set is an error (Mode Off is how to run without).
func Apply(p Policy) (Report, error) {
	var r Report
	if p.Mode == Off {
		r.Missing = append(r.Missing, "switched off in the configuration")
		return r, nil
	}
	abi, err := landlock(p)
	switch {
	case errors.Is(err, errNoLandlock):
		r.Missing = append(r.Missing, "no landlock: "+err.Error())
	case err != nil:
		return r, err
	default:
		r.Landlock = abi
	}
	n, err := seccomp(p.Mode)
	switch {
	case errors.Is(err, errNoSeccomp):
		r.Missing = append(r.Missing, "no seccomp: "+err.Error())
	case err != nil:
		return r, err
	default:
		r.Seccomp, r.Syscalls = string(p.Mode), n
	}
	return r, nil
}
