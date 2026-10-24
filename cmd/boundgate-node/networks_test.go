package main

import (
	"os"
	"path/filepath"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
)

// The daemon's side of several networks: a device that had one keeps it as
// it is, a second one lives beside it, and a switch is one entry in a file
// plus a profile the next turn of the loop picks up.
func TestTheDaemonSwitchesBetweenNetworks(t *testing.T) {
	root := t.TempDir()
	// what a device looks like before it ever heard of networks
	if err := ipc.SaveSettings(filepath.Join(root, "settings.json"), ipc.Settings{ControlAddr: "vpn.net407.com", Name: "mac"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "device.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	nets := &networks{root: root}

	home, ok, err := nets.reload()
	if err != nil || !ok {
		t.Fatalf("reload: %v %v", ok, err)
	}
	if home.ControlAddr != "vpn.net407.com" || home.Dir != "" {
		t.Fatalf("%+v", home)
	}
	if nets.takeProfile() != "" {
		t.Error("a network that was not just chosen wants to come up")
	}

	work, err := nets.Add("Work", ipc.Settings{ControlAddr: "vpn.corp.example", Name: "mac"}, true, "lan-only")
	if err != nil {
		t.Fatal(err)
	}
	// the new network has a state directory of its own, so its key cannot
	// be the one the other control plane knows (R142)
	if work.Path(root) == root {
		t.Fatal("the second network took the state root")
	}
	if _, err := os.Stat(work.Path(root)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "device.key")); err != nil {
		t.Errorf("the first network's key was touched: %v", err)
	}

	cur, ok, err := nets.reload()
	if err != nil || !ok {
		t.Fatalf("reload: %v %v", ok, err)
	}
	if cur.ID != work.ID {
		t.Fatalf("the daemon still runs %q", cur.ID)
	}
	if p := nets.takeProfile(); p != "lan-only" {
		t.Errorf("profile %q, want lan-only", p)
	}
	if p := nets.takeProfile(); p != "" {
		t.Errorf("the profile was taken twice: %q", p)
	}

	// another daemon start reads the same thing from the file
	again := &networks{root: root}
	cur, ok, err = again.reload()
	if err != nil || !ok || cur.ID != work.ID {
		t.Fatalf("after a restart: %+v %v %v", cur, ok, err)
	}
	if err := again.Select("nonsense", ""); err == nil {
		t.Error("an unknown network was selected")
	}

	// the same control plane twice is a mistake, not a second network
	if _, err := again.Add("Work again", ipc.Settings{ControlAddr: "vpn.corp.example"}, false, ""); err == nil {
		t.Error("the same control plane was added twice")
	}

	// giving up the current network falls back to the one that is left. Its
	// files go only once the node that ran it has ended (the next turn of
	// the loop, reload): until then it still talks to its control plane and
	// could write its enrollment or its anchors again
	if err := again.Remove(work.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(work.Path(root)); err != nil {
		t.Errorf("the running network's state went while its node still runs: %v", err)
	}
	if list, _ := again.List(); list.Current != work.ID {
		t.Errorf("the list changed before the node ended: %+v", list)
	}
	cur, ok, err = again.reload()
	if err != nil || !ok || cur.ID != home.ID {
		t.Fatalf("after the removal: %+v %v %v", cur, ok, err)
	}
	if _, err := os.Stat(work.Path(root)); !os.IsNotExist(err) {
		t.Errorf("the removed network's state is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "device.key")); err != nil {
		t.Errorf("the key of the network that stayed is gone: %v", err)
	}

	// and giving up the last one leads back to setup mode, with its key
	// gone: the next network is another device to its control plane (R142)
	if err := again.Remove(home.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := again.reload(); ok || err != nil {
		t.Fatalf("with no networks left: %v %v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(root, "device.key")); !os.IsNotExist(err) {
		t.Errorf("the removed root network's key is still there: %v", err)
	}
	list, err := again.List()
	if err != nil || len(list.Networks) != 0 || list.Current != "" {
		t.Fatalf("%+v %v", list, err)
	}
}

// A fresh device gets its first network through setup mode, and that one
// keeps the state root: the layout of a single-network device does not
// change, and the settings file an older version reads is written as well.
func TestTheFirstNetworkOfAFreshDeviceKeepsTheStateRoot(t *testing.T) {
	root := t.TempDir()
	nets := &networks{root: root}
	if _, ok, err := nets.reload(); ok || err != nil {
		t.Fatalf("a fresh device: %v %v", ok, err)
	}
	n, err := nets.Add("", ipc.Settings{ControlAddr: "vpn.net407.com", Name: "mac"}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if n.Dir != "" || n.Name != "vpn.net407.com" {
		t.Fatalf("%+v", n)
	}
	s, err := ipc.LoadSettings(filepath.Join(root, "settings.json"))
	if err != nil || s.ControlAddr != "vpn.net407.com" || s.Name != "mac" {
		t.Fatalf("settings.json: %+v %v", s, err)
	}
	cur, ok, err := nets.reload()
	if err != nil || !ok || cur.ID != n.ID {
		t.Fatalf("%+v %v %v", cur, ok, err)
	}
}
