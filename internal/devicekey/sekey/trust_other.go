//go:build !unix

package sekey

import "errors"

// The Secure Enclave helper exists on macOS only; elsewhere nothing runs as
// root through findHelper's root branch (os.Geteuid is -1).

func ownerOf(string) (uint32, error) {
	return 0, errors.New("sekey: no file owners on this platform")
}

func checkHelperTrust(string, string, uint32) error {
	return errors.New("sekey: the Secure Enclave helper is macOS only")
}
