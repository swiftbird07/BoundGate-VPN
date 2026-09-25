//go:build unix

package sekey

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The root branch of findHelper, with the owners and modes this machine has:
// a system binary in root's directories passes, anything a user owns or a
// group or everyone may write is refused, whatever runs the test.
func TestHelperTrust(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	if sh, err = filepath.EvalSymlinks(sh); err != nil {
		t.Fatal(err)
	}
	if err := checkHelperTrust(sh, sh, 0); err != nil {
		// a system whose own directories are not root-only has nothing to show here
		t.Skipf("this machine's %s is not in a root-only chain: %v", sh, err)
	}

	uid := uint32(os.Getuid())
	dir := t.TempDir()
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	helper, _ := installHelperIn(t, dir, 0o755)
	exe := filepath.Join(dir, "boundgate-node")

	if uid != 0 {
		// a daemon installed by root, a helper that belongs to a user
		if err := checkHelperTrust(helper, sh, 0); err == nil || !strings.Contains(err.Error(), "neither root nor the owner") {
			t.Fatalf("a user's helper next to a root daemon: %v", err)
		}
	}

	// a directory everyone may write, anywhere above the helper
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(open, 0o777)
	h2, _ := installHelperIn(t, open, 0o755)
	if err := checkHelperTrust(h2, exe, uid); err == nil || !strings.Contains(err.Error(), open+" is writable by everyone") {
		t.Fatalf("world-writable parent: %v", err)
	}

	// a group-writable directory the daemon does not itself live under
	grp := filepath.Join(dir, "grp")
	if err := os.Mkdir(grp, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(grp, 0o775)
	h3, _ := installHelperIn(t, grp, 0o755)
	if err := checkHelperTrust(h3, exe, uid); err == nil || !strings.Contains(err.Error(), grp+" is writable by its group") {
		t.Fatalf("group-writable parent: %v", err)
	}
	// ... which is the daemon's own directory: then the helper is no easier to replace than the daemon
	if err := checkHelperTrust(h3, filepath.Join(grp, "boundgate-node"), uid); err != nil && strings.Contains(err.Error(), grp+" ") {
		t.Fatalf("the daemon's own group-writable directory: %v", err)
	}

	// a link anywhere on the way is not followed
	link := filepath.Join(dir, "link")
	if err := os.Symlink(grp, link); err != nil {
		t.Fatal(err)
	}
	if err := checkHelperTrust(filepath.Join(link, HelperName), exe, uid); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("link: %v", err)
	}
}

// installHelperIn is installHelper into a given directory.
func installHelperIn(t *testing.T, dir string, perm os.FileMode) (string, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, HelperName)
	if err := os.WriteFile(helper, b, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, perm); err != nil {
		t.Fatal(err)
	}
	return helper, dir
}
