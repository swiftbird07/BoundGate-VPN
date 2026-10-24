package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
)

// A device a person uses can belong to more than one mesh -- "Private" at
// home, "Work" at the company -- and the daemon runs one of them at a time
// (issue #13, docs/NETWORKS.md). This is the daemon's side of it: the list
// between the turns of runWith's loop, and the four things the socket may
// ask for.
//
// A server stays single-network: its control plane stands in its
// configuration file. A separated node stays single-network too, because its
// sandbox lets it write exactly one state directory (docs/PRIVSEP.md).
type networks struct {
	root string

	mu   sync.Mutex
	list *ipc.Networks
	// upNext is the routing profile the network that was just selected
	// should come up in, taken once by the loop: someone who picked
	// "Work - Full" does not want to click connect afterwards.
	upNext string
	// removing is the running network that was asked to go: its files go
	// once the node that runs it has ended (reload), not while it still
	// talks to its control plane and could write them again.
	removing string
}

// reload reads the list (taking over an older single-network state the first
// time) and returns the network that is to run.
func (ns *networks) reload() (ipc.Network, bool, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	list, migrated, err := ipc.LoadNetworks(ns.root)
	if err != nil {
		return ipc.Network{}, false, err
	}
	ns.list = list
	if migrated {
		if err := ipc.SaveNetworks(ns.root, list); err != nil {
			return ipc.Network{}, false, err
		}
	}
	if id := ns.removing; id != "" {
		// the node that ran this network has ended: now its files can go
		ns.removing = ""
		if n, ok := list.Get(id); ok {
			if err := n.Discard(ns.root); err != nil {
				return ipc.Network{}, false, err
			}
			if err := list.Remove(id); err != nil {
				return ipc.Network{}, false, err
			}
			if err := ipc.SaveNetworks(ns.root, list); err != nil {
				return ipc.Network{}, false, err
			}
		}
	}
	cur, ok := list.CurrentNetwork()
	if !ok {
		return ipc.Network{}, false, nil
	}
	if _, err := cur.Prepare(ns.root); err != nil {
		return ipc.Network{}, false, err
	}
	return cur, true, nil
}

// takeProfile is the profile the loop should bring the network up in, once.
func (ns *networks) takeProfile() string {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	p := ns.upNext
	ns.upNext = ""
	return p
}

// List implements ipc.Networker.
func (ns *networks) List() (ipc.NetworkList, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.list == nil {
		return ipc.NetworkList{}, nil
	}
	out := ipc.NetworkList{Current: ns.list.Current, Networks: make([]ipc.Network, len(ns.list.List))}
	copy(out.Networks, ns.list.List)
	return out, nil
}

// Add stores a network and prepares its state directory.
func (ns *networks) Add(name string, s ipc.Settings, selectIt bool, profile string) (ipc.Network, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.list == nil {
		ns.list = &ipc.Networks{}
	}
	for _, n := range ns.list.List {
		if n.ControlAddr == s.ControlAddr {
			return ipc.Network{}, fmt.Errorf("the network %q already has the control plane %s", n.Name, n.ControlAddr)
		}
	}
	n, err := ns.list.Add(name, s)
	if err != nil {
		return ipc.Network{}, err
	}
	if err := n.Create(ns.root); err != nil {
		ns.list.Remove(n.ID)
		return ipc.Network{}, err
	}
	// the network that owns the state root also writes settings.json, so a
	// device with one network keeps the file older versions read
	if n.Dir == "" {
		if err := ipc.SaveSettings(filepath.Join(ns.root, "settings.json"), n.Settings()); err != nil {
			return ipc.Network{}, err
		}
	}
	if selectIt {
		ns.list.Current, ns.upNext = n.ID, profile
	}
	if err := ipc.SaveNetworks(ns.root, ns.list); err != nil {
		return ipc.Network{}, err
	}
	return n, nil
}

// Select makes id the network that runs.
func (ns *networks) Select(id, profile string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.list == nil || ns.list.Find(id) < 0 {
		return fmt.Errorf("no network %q (boundgatectl networks)", id)
	}
	ns.list.Current, ns.upNext = id, profile
	return ipc.SaveNetworks(ns.root, ns.list)
}

// Remove gives up a network: its files first, then the entry. This is also
// what `boundgatectl reset` does to the network it is in.
func (ns *networks) Remove(id string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.list == nil {
		return errors.New("this daemon has no networks")
	}
	n, ok := ns.list.Get(id)
	if !ok {
		return fmt.Errorf("no network %q (boundgatectl networks)", id)
	}
	ns.upNext = ""
	if id == ns.list.Current {
		// the node that runs it still talks to its control plane and would
		// write its enrollment or its anchors again: the socket ends that
		// node (ErrSwitch), and the next turn of the loop takes the files
		ns.removing = id
		return nil
	}
	if err := n.Discard(ns.root); err != nil {
		return err
	}
	if err := ns.list.Remove(id); err != nil {
		return err
	}
	return ipc.SaveNetworks(ns.root, ns.list)
}
