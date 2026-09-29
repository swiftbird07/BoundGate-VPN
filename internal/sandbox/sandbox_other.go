//go:build !linux

package sandbox

import "errors"

// Apply: the sandbox is Linux's seccomp and Landlock.
func Apply(Policy) (Report, error) {
	return Report{}, errors.New("sandbox: not on this platform")
}
