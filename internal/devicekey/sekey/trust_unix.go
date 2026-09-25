//go:build unix

package sekey

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func ownerOf(path string) (uint32, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: no owner information", path)
	}
	return st.Uid, nil
}

// checkHelperTrust is findHelper's test as root, for resolved paths (no
// links): the helper must be no easier to replace than the daemon's own
// executable exe. The helper and every directory above it up to / belong to
// root or to exe's owner, none is writable by others, and none by its group
// unless the daemon already depends on that directory itself (it is above
// exe too): /Applications, writable by the group admin, above an app bundle
// (R74). A daemon installed root-only (deploy/macos/install.sh) therefore
// gets a root-only chain.
func checkHelperTrust(path, exe string, exeOwner uint32) error {
	exeDir := filepath.Dir(exe)
	aboveExe := func(dir string) bool {
		return dir == exeDir || dir == "/" || strings.HasPrefix(exeDir, strings.TrimSuffix(dir, "/")+"/")
	}
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: no owner information", p)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", p)
		}
		if st.Uid != 0 && st.Uid != exeOwner {
			return fmt.Errorf("%s belongs to uid %d, neither root nor the owner of boundgate-node", p, st.Uid)
		}
		perm := fi.Mode().Perm()
		if perm&0o002 != 0 {
			return fmt.Errorf("%s is writable by everyone (%s)", p, perm)
		}
		if perm&0o020 != 0 && !(fi.IsDir() && aboveExe(p)) {
			return fmt.Errorf("%s is writable by its group %d (%s)", p, st.Gid, perm)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}
