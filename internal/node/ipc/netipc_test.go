package ipc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// testNets is a daemon's list of networks, as far as the socket sees it.
type testNets struct {
	list      NetworkList
	added     []NewNetwork
	selected  []string
	removed   []string
	failAdd   error
	failSelct error
}

func (t *testNets) List() (NetworkList, error) { return t.list, nil }

func (t *testNets) Add(name string, s Settings, selectIt bool, profile string) (Network, error) {
	if t.failAdd != nil {
		return Network{}, t.failAdd
	}
	t.added = append(t.added, NewNetwork{Name: name, ControlAddr: s.ControlAddr, NodeName: s.Name, Select: selectIt, Profile: profile})
	n := Network{ID: slug(name), Name: name, ControlAddr: s.ControlAddr}
	t.list.Networks = append(t.list.Networks, n)
	if selectIt {
		t.list.Current = n.ID
	}
	return n, nil
}

func (t *testNets) Select(id, profile string) error {
	if t.failSelct != nil {
		return t.failSelct
	}
	t.selected = append(t.selected, id+" "+profile)
	t.list.Current = id
	return nil
}

func (t *testNets) Remove(id string) error { t.removed = append(t.removed, id); return nil }

func serveNode(t *testing.T, opt Options) (*Client, *node.Node, chan error) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bgnet") // unix socket paths are short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	n, err := node.New(node.Config{Name: "mac", StateDir: filepath.Join(dir, "state"),
		ControlAddr: "control.test:443", Roles: []string{"endpoint"}, NetworkID: "home", NetworkName: "Home"})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, sock, n, opt) }()
	c := NewClient(sock)
	for i := 0; ; i++ {
		if _, err = c.Status(); err == nil {
			return c, n, done
		}
		if i > 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Choosing another network answers first and then ends this node, so its
// routes are gone before the next network starts (R143).
func TestSelectingAnotherNetworkEndsTheNodeAfterTheAnswer(t *testing.T) {
	nets := &testNets{list: NetworkList{Current: "home", Networks: []Network{
		{ID: "home", Name: "Home", ControlAddr: "vpn.net407.com"},
		{ID: "work", Name: "Work", ControlAddr: "vpn.corp.example", Dir: "networks/work"},
	}}}
	c, _, done := serveNode(t, Options{Nets: nets})

	list, err := c.Networks()
	if err != nil {
		t.Fatal(err)
	}
	if list.Current != "home" || len(list.Networks) != 2 || list.Single != "" {
		t.Fatalf("%+v", list)
	}
	if err := c.SelectNetwork("work", "full"); err != nil {
		t.Fatal(err)
	}
	if len(nets.selected) != 1 || nets.selected[0] != "work full" {
		t.Fatalf("selected %v", nets.selected)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrSwitch) {
			t.Fatalf("the daemon got %v, want ErrSwitch", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the socket kept running: the daemon never learns of the switch")
	}
}

// The status says which network this is, so an app with several of them can
// show where it is.
func TestTheStatusNamesTheNetwork(t *testing.T) {
	c, _, _ := serveNode(t, Options{Nets: &testNets{}})
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.NetworkID != "home" || st.NetworkName != "Home" {
		t.Fatalf("status says %q / %q", st.NetworkID, st.NetworkName)
	}
}

// Adding a network takes the address through the same validation as
// `configure`, and a daemon that cannot have several says why instead of
// pretending to store one.
func TestAddingANetworkValidatesAndASingleNetworkDaemonRefuses(t *testing.T) {
	nets := &testNets{}
	c, _, _ := serveNode(t, Options{Nets: nets})
	if _, err := c.AddNetwork(NewNetwork{Name: "Work", ControlAddr: "vpn.corp.example", NodeName: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if len(nets.added) != 1 || nets.added[0].ControlAddr != "vpn.corp.example" || nets.added[0].Select {
		t.Fatalf("added %+v", nets.added)
	}
	if err := c.RemoveNetwork("work"); err != nil {
		t.Fatal(err)
	}
	if len(nets.removed) != 1 || nets.removed[0] != "work" {
		t.Fatalf("removed %v", nets.removed)
	}

	// a node that got its control plane from a configuration file
	single, _, _ := serveNode(t, Options{SingleNetwork: "the control plane of this node stands in its configuration file (control.addr)"})
	list, err := single.Networks()
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Networks) != 1 || list.Networks[0].ControlAddr != "control.test:443" || list.Single == "" {
		t.Fatalf("%+v", list)
	}
	_, err = single.AddNetwork(NewNetwork{Name: "Work", ControlAddr: "vpn.corp.example"})
	if err == nil || !contains(err.Error(), "configuration file") {
		t.Fatalf("add: %v, want the reason", err)
	}
	if err := single.SelectNetwork("work", ""); err == nil || !contains(err.Error(), "configuration file") {
		t.Fatalf("select: %v", err)
	}
	if err := single.RemoveNetwork("work"); err == nil {
		t.Fatal("a single-network daemon removed a network")
	}
}
