package ipc

import (
	"os"
	"path/filepath"
	"testing"
)

// The network a daemon already has keeps the state root: its key, its pin and
// the fingerprint the control plane knows must survive learning about a
// second network.
func TestAnOldStateBecomesTheFirstNetworkWithoutMovingAnything(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(filepath.Join(dir, "settings.json"), Settings{ControlAddr: "vpn.net407.com", Name: "nas"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "device.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	ns, migrated, err := LoadNetworks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Error("the old state was not taken over")
	}
	cur, ok := ns.CurrentNetwork()
	if !ok {
		t.Fatal("no current network")
	}
	if cur.ControlAddr != "vpn.net407.com" || cur.NodeName != "nas" {
		t.Errorf("the settings were lost: %+v", cur)
	}
	if cur.Dir != "" || cur.Path(dir) != dir {
		t.Errorf("the first network was moved to %q", cur.Path(dir))
	}
	if err := SaveNetworks(dir, ns); err != nil {
		t.Fatal(err)
	}
	// the key stayed, and reading again changes nothing
	if _, err := os.Stat(filepath.Join(dir, "device.key")); err != nil {
		t.Errorf("the device key is gone: %v", err)
	}
	again, migrated, err := LoadNetworks(dir)
	if err != nil || migrated {
		t.Fatalf("second read: migrated=%v err=%v", migrated, err)
	}
	if again.Current != ns.Current || len(again.List) != 1 {
		t.Errorf("read back %+v", again)
	}
}

// A second network gets a directory of its own, so node.New puts its key,
// pin and enrollment beside it instead of over the first network's -- while
// the first network keeps the state root and the layout every single-network
// device has.
func TestASecondNetworkGetsItsOwnDirectory(t *testing.T) {
	dir := t.TempDir()
	ns := &Networks{}
	home, err := ns.Add("Home", Settings{ControlAddr: "vpn.net407.com", Name: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	if home.Dir != "" || home.Path(dir) != dir {
		t.Fatalf("the first network was put in %q", home.Path(dir))
	}
	work, err := ns.Add("Work", Settings{ControlAddr: "vpn.corp.example", Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if work.ID != "work" || work.Dir != filepath.Join("networks", "work") {
		t.Fatalf("%+v", work)
	}
	p, err := work.Prepare(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "networks", "work") {
		t.Fatalf("path %q", p)
	}
	if fi, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if m := fi.Mode().Perm(); m != 0o700 && os.Getenv("GOOS") != "windows" {
		t.Errorf("mode %v", m)
	}

	// a second one with the same name does not take the same directory
	again, err := ns.Add("Work", Settings{ControlAddr: "vpn.other.example"})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID == work.ID || again.Dir == work.Dir {
		t.Fatalf("%+v collides with %+v", again, work)
	}
	if again.Name != "Work" {
		t.Errorf("name %q", again.Name)
	}
	// a nameless network is known by its address
	addr, err := ns.Add("", Settings{ControlAddr: "vpn.lab.example"})
	if err != nil {
		t.Fatal(err)
	}
	if addr.Name != "vpn.lab.example" || addr.ID != "vpn-lab-example" {
		t.Errorf("%+v", addr)
	}
	if _, err := ns.Add("Nope", Settings{ControlAddr: ""}); err == nil {
		t.Error("a network without a control plane was accepted")
	}
}

// Removing a network that has a directory takes its key with it; removing
// the one that owns the state root only unties it from its control plane,
// because the root holds the daemon's own files as well.
func TestRemovingANetworkTakesItsOwnStateAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	ns := &Networks{}
	root, _ := ns.Add("Home", Settings{ControlAddr: "vpn.net407.com"})
	ns.Current = root.ID
	work, _ := ns.Add("Work", Settings{ControlAddr: "vpn.corp.example"})
	if _, err := work.Prepare(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"device.key", "control.pin", "settings.json", "netstate.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work.Path(dir), "device.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := work.Discard(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(work.Path(dir)); !os.IsNotExist(err) {
		t.Errorf("the network's directory is still there: %v", err)
	}
	if err := ns.Remove(work.ID); err != nil {
		t.Fatal(err)
	}
	if ns.Current != root.ID || len(ns.List) != 1 {
		t.Fatalf("%+v", ns)
	}

	if err := root.Discard(dir); err != nil {
		t.Fatal(err)
	}
	// the journal is the daemon's, not the network's to delete
	if _, err := os.Stat(filepath.Join(dir, "netstate.json")); err != nil {
		t.Errorf("netstate.json is gone: %v", err)
	}
	// the key goes with the network, root or not: the next network must not
	// be the same device to another control plane (R142)
	for _, f := range []string{"device.key", "control.pin", "settings.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s survived: %v", f, err)
		}
	}
	if err := ns.Remove(root.ID); err != nil {
		t.Fatal(err)
	}
	if ns.Current != "" {
		t.Errorf("current is %q with no networks left", ns.Current)
	}
	// a directory a removed network left behind is not taken over
	if err := os.MkdirAll(work.Path(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := work.Create(dir); err == nil {
		t.Fatal("a leftover directory was taken over as the new network's")
	}
	os.RemoveAll(work.Path(dir))
	if err := work.Create(dir); err != nil {
		t.Fatal(err)
	}
}

// A directory that the daemon did not create is not deleted, whatever the
// file says.
func TestAHandWrittenStateDirectoryIsNotDeleted(t *testing.T) {
	dir := t.TempDir()
	n := Network{ID: "work", Name: "Work", ControlAddr: "vpn.corp.example", Dir: "../../etc"}
	if err := n.Discard(dir); err == nil {
		t.Fatal("it would have deleted it")
	}
	ns := &Networks{Current: "work", List: []Network{n}}
	if err := SaveNetworks(dir, ns); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadNetworks(dir); err == nil {
		t.Error("the file was accepted")
	}
}

func TestABrokenNetworkFileIsRefusedWithItsReason(t *testing.T) {
	cases := map[string]*Networks{
		"two networks with the id": {List: []Network{
			{ID: "work", ControlAddr: "a.example"}, {ID: "work", ControlAddr: "b.example"}}},
		"is not in the list":                      {Current: "gone", List: []Network{{ID: "work", ControlAddr: "a.example"}}},
		"control plane address is required":       {List: []Network{{ID: "work"}}},
		"is not a name for a directory":           {List: []Network{{ID: "../work", ControlAddr: "a.example"}}},
		"points at \"networks/other\" instead of": {List: []Network{{ID: "work", ControlAddr: "a.example", Dir: "networks/other"}}},
	}
	for want, ns := range cases {
		t.Run(want, func(t *testing.T) {
			dir := t.TempDir()
			if err := SaveNetworks(dir, ns); err != nil {
				t.Fatal(err)
			}
			_, _, err := LoadNetworks(dir)
			if err == nil {
				t.Fatal("accepted")
			}
			if !contains(err.Error(), want) {
				t.Fatalf("error %q does not say %q", err, want)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A second network whose name makes the same slug as the first gets a
// number, and that number has to fit: a slug at its full length with a
// number behind it was no slug any more, and the file was refused on the
// next start, with the daemon unable to come up at all.
func TestANumberedIDIsStillASlug(t *testing.T) {
	ns := &Networks{}
	name := "Northern Lights Research Network" // its slug is cut at 24
	first, err := ns.Add(name, Settings{ControlAddr: "vpn.one.example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.ID) != maxSlug {
		t.Fatalf("id %q: the test needs a name whose slug is at the full length", first.ID)
	}
	for i := 0; i < 10; i++ {
		n, err := ns.Add(name, Settings{ControlAddr: "vpn.two.example"})
		if err != nil {
			t.Fatal(err)
		}
		if slug(n.ID) != n.ID || n.ID == first.ID {
			t.Fatalf("id %q is not a slug or collides", n.ID)
		}
	}
	if err := ns.validate(); err != nil {
		t.Fatalf("the file would be refused on the next start: %v", err)
	}
	if n := ns.List[1].ID; n != "northern-lights-researc2" {
		t.Errorf("second id %q", n)
	}
	if n := ns.List[10].ID; n != "northern-lights-resear11" {
		t.Errorf("eleventh id %q", n)
	}
}
