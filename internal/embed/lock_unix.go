//go:build unix

package embed

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// lockDir takes an exclusive lock on the state directory: the app and its
// network extension share it, and only one of them may run a node on it.
// The lock goes with the process, also when it is killed.
func lockDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "engine.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return f, nil
}
