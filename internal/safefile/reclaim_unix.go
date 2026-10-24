//go:build !windows

package safefile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Reclaim frees the name path for a file of this process's own: whatever
// else sits there -- a symbolic link, a directory, a file of another user --
// is removed, and the caller may write. It returns whether something was
// removed.
//
// This is for a privileged process that owns a directory someone less
// privileged writes to as well (the state directory under privilege
// separation, docs/PRIVSEP.md): that someone may create an entry under a
// name the privileged process uses and so keep it from ever writing that
// file again, or from reading it on its next start. The directory's owner
// may remove any entry in it, sticky bit or not, so it does.
//
// A regular file of this user that has several names is left alone: the
// worker cannot make a hard link, so such a file is someone's doing on the
// machine, and refusing to read it (ReadOwn) says so more clearly than
// quietly replacing it.
func Reclaim(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if fi.Mode().IsRegular() && ok && int(st.Uid) == os.Geteuid() {
		return false, nil
	}
	// RemoveAll on a symbolic link removes the link, not what it points to
	if err := os.RemoveAll(path); err != nil {
		return false, fmt.Errorf("safefile: reclaim %s: %w", path, err)
	}
	return true, nil
}
