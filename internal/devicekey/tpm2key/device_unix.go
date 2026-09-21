//go:build !windows

package tpm2key

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// DefaultDevice is the kernel's TPM resource manager.
const DefaultDevice = "/dev/tpmrm0"

func openDevice(path string) (transport.TPMCloser, error) { return linuxtpm.Open(path) }
