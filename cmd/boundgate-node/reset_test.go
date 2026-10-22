package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
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
		reset := resetFunc(true, nil, current{stateDir: dir, settingsPath: settings})

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
		if err := resetFunc(false, nil, current{stateDir: dir, settingsPath: settings})(false); err != nil {
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
		if err := resetFunc(true, sep, current{stateDir: dir})(true); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(asked, []bool{true}) {
			t.Fatalf("the parent was asked %v, want [true]", asked)
		}
		if _, err := os.Stat(filepath.Join(dir, "device.key")); err != nil {
			t.Fatalf("the worker deleted the parent's key file: %v", err)
		}
		if err := resetFunc(true, &separated{}, current{stateDir: dir})(true); err == nil {
			t.Fatal("a worker without a way to ask its parent: accepted")
		}
	})
}

// fakeNets records what the daemon's list of networks was asked to do.
type fakeNets struct {
	removed []string
	list    ipc.NetworkList
}

func (f *fakeNets) List() (ipc.NetworkList, error) { return f.list, nil }
func (f *fakeNets) Add(string, ipc.Settings, bool, string) (ipc.Network, error) {
	return ipc.Network{}, nil
}
func (f *fakeNets) Select(string, string) error { return nil }
func (f *fakeNets) Remove(id string) error      { f.removed = append(f.removed, id); return nil }

// With several networks, forgetting the control plane means giving up this
// network -- not emptying a state directory that another network's files
// would then be missing from.
func TestResetOfOneOfSeveralNetworksRemovesThatNetwork(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	nets := &fakeNets{}
	cur := current{stateDir: dir, settingsPath: filepath.Join(dir, "settings.json"), id: "work", name: "Work", nets: nets}

	if err := resetFunc(false, nil, cur)(false); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nets.removed, []string{"work"}) {
		t.Fatalf("removed %v, want [work]", nets.removed)
	}

	// a new identity for the same network is not a removal: the files go,
	// the network stays in the list
	if err := resetFunc(false, nil, cur)(true); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nets.removed, []string{"work"}) {
		t.Fatalf("-new-identity removed a network: %v", nets.removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "device.key")); !os.IsNotExist(err) {
		t.Fatalf("the device key survived -new-identity: %v", err)
	}
}
