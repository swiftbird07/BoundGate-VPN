//go:build unix

package db

import "golang.org/x/sys/unix"

// freeBytes is the room left on the filesystem that holds dir, as the
// unprivileged limit sees it (Bavail, not Bfree).
func freeBytes(dir string) uint64 {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0
	}
	return uint64(st.Bavail) * uint64(st.Bsize)
}
