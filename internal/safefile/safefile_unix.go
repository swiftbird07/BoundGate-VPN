//go:build !windows

package safefile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func openOf(path string, uid int) (*os.File, error) {
	if uid < 0 {
		uid = os.Geteuid()
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symbolic link", ErrNotOwn, path)
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		err = fmt.Errorf("%w: %s is not a regular file", ErrNotOwn, path)
	case !ok:
		err = fmt.Errorf("%w: %s: no owner information", ErrNotOwn, path)
	case int(st.Uid) != uid:
		err = fmt.Errorf("%w: %s belongs to uid %d, not to uid %d", ErrNotOwn, path, st.Uid, uid)
	case st.Nlink != 1:
		err = fmt.Errorf("%w: %s has %d names (hard links)", ErrNotOwn, path, st.Nlink)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
