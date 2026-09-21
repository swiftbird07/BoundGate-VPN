package ipc

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestForget(t *testing.T) {
	all := []string{"settings.json", "control.pin", "admin_trust.json", "device.key", "device.sekey", "device.crt", "netstate.json"}
	for _, c := range []struct {
		newIdentity bool
		left        []string
	}{
		{false, []string{"device.crt", "device.key", "device.sekey", "netstate.json"}},
		{true, []string{"netstate.json"}},
	} {
		dir := t.TempDir()
		for _, f := range all {
			os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600)
		}
		if err := Forget(dir, filepath.Join(dir, "settings.json"), c.newIdentity); err != nil {
			t.Fatal(err)
		}
		var left []string
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			left = append(left, e.Name())
		}
		if !slices.Equal(left, c.left) {
			t.Errorf("new identity %v: left %v, want %v", c.newIdentity, left, c.left)
		}
		// a second reset finds nothing and is not an error
		if err := Forget(dir, filepath.Join(dir, "settings.json"), c.newIdentity); err != nil {
			t.Fatal(err)
		}
	}
}
