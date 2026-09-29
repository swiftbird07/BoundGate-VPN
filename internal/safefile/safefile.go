// Package safefile reads and writes the files a privileged process keeps in
// a directory that a less privileged one may write to: the device key and
// the network journal of boundgate-node, whose state directory belongs to
// the unprivileged worker under privilege separation (docs/PRIVSEP.md).
//
// Whoever can write the directory can put a symbolic link or a hard link
// where such a file is expected. Read through it, root would take another
// file for its key; written through it, root would overwrite any file on
// the machine. ReadOwn therefore reads only a regular file of this process's
// own user with no other name, and WriteAtomic writes a fresh file under a
// random name and renames it into place, which replaces a link instead of
// following it.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrNotOwn is returned for a file that is not a plain file of this
// process's user: a link, another owner, or one with several names.
var ErrNotOwn = errors.New("safefile: not a plain file of this user")

// ReadOwn reads at most max bytes of path, which must be a regular file
// owned by this process's user with exactly one name, opened without
// following a symbolic link. A missing file is an error that satisfies
// errors.Is(err, os.ErrNotExist).
func ReadOwn(path string, max int64) ([]byte, error) {
	f, err := openOwn(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("safefile: %s is larger than %d bytes", path, max)
	}
	return b, nil
}

// WriteAtomic writes b to path with mode 0600: into a new file with a
// random name in the same directory (created exclusively, so nothing that
// already has that name is followed), synced, then renamed over path.
func WriteAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
