//go:build windows

package tpm2key

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// DefaultDevice on Windows is the TPM Base Services (tbs.dll), which is also
// the resource manager: every context gets its own view of transient handles.
const DefaultDevice = "tbs"

func openDevice(path string) (transport.TPMCloser, error) {
	if path != DefaultDevice {
		return nil, fmt.Errorf("on Windows the TPM is reached through TPM Base Services: leave tpm_device empty or set it to %q", DefaultDevice)
	}
	return windowstpm.Open()
}
