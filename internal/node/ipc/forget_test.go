package ipc

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestForget(t *testing.T) {
	all := []string{"settings.json", "control.pin", "admin_trust.json", "bindings_seen.json", "enrollment.json",
		"device.key", "device.sekey", "device.crt", "netstate.json"}
	for _, c := range []struct {
		name        string
		settings    string // "" : the control plane stands in the configuration
		newIdentity bool
		left        []string
	}{
		{"the control plane", "settings.json", false, []string{"device.crt", "device.key", "device.sekey", "netstate.json"}},
		{"and the identity", "settings.json", true, []string{"netstate.json"}},
		// a node configured by file has no settings file to remove, and an
		// empty path must not reach the state directory itself
		{"the identity alone", "", true, []string{"netstate.json", "settings.json"}},
	} {
		dir := t.TempDir()
		for _, f := range all {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		settings := c.settings
		if settings != "" {
			settings = filepath.Join(dir, settings)
		}
		if err := Forget(dir, settings, c.newIdentity); err != nil {
			t.Fatal(err)
		}
		var left []string
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: the state directory itself went: %v", c.name, err)
		}
		for _, e := range entries {
			left = append(left, e.Name())
		}
		if !slices.Equal(left, c.left) {
			t.Errorf("%s: left %v, want %v", c.name, left, c.left)
		}
		// a second reset finds nothing and is not an error
		if err := Forget(dir, settings, c.newIdentity); err != nil {
			t.Fatal(err)
		}
	}
}
