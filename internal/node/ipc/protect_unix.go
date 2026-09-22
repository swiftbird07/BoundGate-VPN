//go:build !windows

package ipc

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
)

// DefaultSocket is where the daemon listens unless configured otherwise.
func DefaultSocket() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/boundgate/node.sock"
	}
	return "/run/boundgate/node.sock"
}

// protect makes the socket usable by root and, when group is set, that
// group (name or gid): mode 0660.
func protect(socketPath, group string, users []string) error {
	if len(users) > 0 {
		return fmt.Errorf("ipc: socket_users is for Windows; use socket_group")
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return err
	}
	if group == "" {
		return nil
	}
	gid, err := strconv.Atoi(group)
	if err != nil {
		g, gerr := user.LookupGroup(group)
		if gerr != nil {
			return fmt.Errorf("ipc: socket group: %w", gerr)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	if err := os.Chown(socketPath, -1, gid); err != nil {
		return fmt.Errorf("ipc: socket group %s: %w", group, err)
	}
	return nil
}
