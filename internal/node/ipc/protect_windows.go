//go:build windows

package ipc

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// DefaultSocket is where the daemon listens unless configured otherwise:
// an AF_UNIX socket (Windows 10 1803 and later) under ProgramData.
func DefaultSocket() string {
	return filepath.Join(Dir(), "node.sock")
}

// Dir is BoundGate's directory under ProgramData: configuration, state,
// logs and the socket.
func Dir() string { return filepath.Join(ProgramData(), "BoundGate") }

// ProgramData is %ProgramData%, normally C:\ProgramData.
func ProgramData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// protect gives the socket file an explicit DACL: SYSTEM and Administrators,
// and when group is set (a local group name or SID string, e.g. "Users" for
// the tray app of a standard user) that group may connect as well. Windows
// checks write access to the socket file on connect.
func protect(socketPath, group string) error {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if group != "" {
		sid, err := windows.StringToSid(group)
		if err != nil {
			sid, _, _, err = windows.LookupSID("", group)
			if err != nil {
				return fmt.Errorf("ipc: socket group %q: %w", group, err)
			}
		}
		sddl += fmt.Sprintf("(A;;GRGW;;;%s)", sid.String())
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(socketPath, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("ipc: protect %s: %w", socketPath, err)
	}
	return nil
}
