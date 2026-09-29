//go:build !windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadOwnRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	if err := WriteAtomic(key, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadOwn(key, 64); err != nil || string(b) != "secret" {
		t.Fatalf("own file: %q %v", b, err)
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	other := filepath.Join(dir, "other")
	_ = os.WriteFile(other, []byte("not the key"), 0o600)
	sym := filepath.Join(dir, "sym.key")
	_ = os.Symlink(other, sym)
	if _, err := ReadOwn(sym, 64); !errors.Is(err, ErrNotOwn) {
		t.Fatalf("symbolic link read: %v", err)
	}
	hard := filepath.Join(dir, "hard.key")
	_ = os.Link(other, hard)
	if _, err := ReadOwn(hard, 64); !errors.Is(err, ErrNotOwn) {
		t.Fatalf("hard link read: %v", err)
	}
	if _, err := ReadOwn(dir, 64); !errors.Is(err, ErrNotOwn) {
		t.Fatalf("directory read: %v", err)
	}
	if _, err := ReadOwn(filepath.Join(dir, "missing"), 64); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := ReadOwn(key, 3); err == nil {
		t.Fatal("a file above the limit was read")
	}
}

// A link placed where the file is written is replaced, not followed.
func TestWriteAtomicReplacesALink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	_ = os.WriteFile(victim, []byte("keep"), 0o600)
	path := filepath.Join(dir, "netstate.json")
	_ = os.Symlink(victim, path)
	_ = os.Symlink(victim, path+".tmp")
	if err := WriteAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("the link target was written: %q", b)
	}
	if b, err := ReadOwn(path, 64); err != nil || string(b) != "new" {
		t.Fatalf("%q %v", b, err)
	}
}
