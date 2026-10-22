package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A node whose control plane stands in its configuration file keeps that
// address but may give up its identity; a separated worker has its parent do
// it, because those files are the parent's.
func TestResetFunc(t *testing.T) {
	t.Run("from a file: the address stays, the identity can go", func(t *testing.T) {
		dir := t.TempDir()
		settings := filepath.Join(dir, "settings.json")
		for _, f := range []string{"settings.json", "control.pin", "device.key", "device.crt"} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		reset := resetFunc(true, nil, dir, settings)

		err := reset(false)
		if err == nil || !strings.Contains(err.Error(), "-new-identity") {
			t.Fatalf("plain reset: %v, want a refusal naming -new-identity", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "control.pin")); err != nil {
			t.Fatalf("the refused reset deleted something: %v", err)
		}
		if err := reset(true); err != nil {
			t.Fatal(err)
		}
		var left []string
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			left = append(left, e.Name())
		}
		// the settings file is not this node's to remove: the configuration
		// names the control plane, and the file would be ignored anyway
		if want := []string{"settings.json"}; !slices.Equal(left, want) {
			t.Fatalf("left %v, want %v", left, want)
		}
	})

	t.Run("without a file: as before", func(t *testing.T) {
		dir := t.TempDir()
		settings := filepath.Join(dir, "settings.json")
		os.WriteFile(settings, []byte("x"), 0o600)
		os.WriteFile(filepath.Join(dir, "device.key"), []byte("x"), 0o600)
		if err := resetFunc(false, nil, dir, settings)(false); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(settings); !os.IsNotExist(err) {
			t.Fatalf("settings.json survived a plain reset: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "device.key")); err != nil {
			t.Fatalf("the device key went with a plain reset: %v", err)
		}
	})

	t.Run("separated: the parent does it", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "device.key"), []byte("x"), 0o600)
		var asked []bool
		sep := &separated{forget: func(newIdentity bool) error { asked = append(asked, newIdentity); return nil }}
		if err := resetFunc(true, sep, dir, "")(true); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(asked, []bool{true}) {
			t.Fatalf("the parent was asked %v, want [true]", asked)
		}
		if _, err := os.Stat(filepath.Join(dir, "device.key")); err != nil {
			t.Fatalf("the worker deleted the parent's key file: %v", err)
		}
		if err := resetFunc(true, &separated{}, dir, "")(true); err == nil {
			t.Fatal("a worker without a way to ask its parent: accepted")
		}
	})
}
