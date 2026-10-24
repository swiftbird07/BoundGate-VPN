//go:build !windows

package anchors

import (
	"os"
	"path/filepath"
	"testing"
)

// The parent owns the state directory; the worker writes to it as well. A
// file or directory of the worker's under one of the parent's names must
// not keep the parent from its anchors (R145): the writer removes it and
// goes on as if the name were free. A reader of another user's files (the
// worker) refuses it, as before.
func TestTheWriterReclaimsASquattedName(t *testing.T) {
	dir := t.TempDir()
	for _, squat := range []func(string) error{
		func(p string) error { return os.Mkdir(p, 0o755) },
		func(p string) error { return os.Symlink("/etc/hostname", p) },
	} {
		for _, n := range Names {
			os.RemoveAll(filepath.Join(dir, n))
			if err := squat(filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
		f, err := Open(Options{Dir: dir, Owner: -1, Shared: true})
		if err != nil {
			t.Fatalf("open with squatted names: %v", err)
		}
		if _, ok, err := f.Pin(); err != nil || ok {
			t.Fatalf("pin with a squatted name: %v %v", ok, err)
		}
		if err := f.SetPin(key(1)); err != nil {
			t.Fatalf("pin over a squatted name: %v", err)
		}
		if cur, ok, err := f.Pin(); err != nil || !ok || cur != key(1) {
			t.Fatalf("the pin afterwards: %v %v %v", cur, ok, err)
		}
		if _, err := f.Trust(); err != nil {
			t.Fatalf("trust with a squatted name: %v", err)
		}
		if _, err := f.History(); err != nil {
			t.Fatalf("history with a squatted name: %v", err)
		}
		for _, n := range Names {
			if fi, err := os.Lstat(filepath.Join(dir, n)); err == nil && !fi.Mode().IsRegular() {
				t.Fatalf("%s is still what the worker put there", n)
			}
		}
	}
	// a reader never removes anything: it is not its directory
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, TrustFile)); err != nil {
		t.Fatal(err)
	}
	r, err := Open(Options{Dir: dir, Owner: -1, Shared: true, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Trust(); err == nil {
		t.Fatal("a reader read through a link")
	}
	if fi, err := os.Lstat(filepath.Join(dir, TrustFile)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("a reader removed the link")
	}
}
