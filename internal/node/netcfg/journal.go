package netcfg

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// Journal wraps a Configurator and records what it changed on the host in a
// small state file, so that a daemon that died without cleaning up (crash,
// kill -9, power loss with a persistent route table) can undo it on the next
// start. Routes through the TUN vanish with the device; bypass host routes
// do not, and a stale one silently pins a hub or the control plane to a
// gateway of a network the machine has left.
type Journal struct {
	Configurator
	path string

	mu sync.Mutex
	st journalState
}

type journalRoute struct {
	Dst   netip.Prefix `json:"dst"`
	Iface string       `json:"iface"`
}

type journalState struct {
	Routes []journalRoute `json:"routes,omitempty"`
	Bypass []netip.Addr   `json:"bypass,omitempty"`
	NAT    string         `json:"nat_iface,omitempty"`
}

// NewJournal journals c into path (created 0600 next to the node's state).
func NewJournal(c Configurator, path string) *Journal {
	return &Journal{Configurator: c, path: path}
}

// Recover undoes what a previous process left behind and returns how many
// entries it removed. Errors of individual removals are ignored: most
// entries are gone already.
func (j *Journal) Recover(ctx context.Context) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, err := os.ReadFile(j.path)
	if err != nil {
		return 0
	}
	var old journalState
	if json.Unmarshal(b, &old) != nil {
		_ = os.Remove(j.path)
		return 0
	}
	n := 0
	for _, r := range old.Routes {
		_ = j.Configurator.DelRoute(ctx, r.Dst, r.Iface)
		n++
	}
	for _, h := range old.Bypass {
		_ = j.Configurator.DelBypass(ctx, h)
		n++
	}
	if old.NAT != "" {
		_ = j.Configurator.SetNAT(ctx, netip.Prefix{}, nil, old.NAT)
		n++
	}
	j.st = journalState{}
	_ = os.Remove(j.path)
	return n
}

// save writes the state; called with mu held.
func (j *Journal) save() {
	if len(j.st.Routes) == 0 && len(j.st.Bypass) == 0 && j.st.NAT == "" {
		_ = os.Remove(j.path)
		return
	}
	b, _ := json.MarshalIndent(j.st, "", "  ")
	tmp := j.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return
	}
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, j.path)
	}
}

func (j *Journal) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	return j.Configurator.CreateTUN(name, mtu)
}

func (j *Journal) AddRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	if err := j.Configurator.AddRoute(ctx, dst, ifname); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, r := range j.st.Routes {
		if r.Dst == dst && r.Iface == ifname {
			return nil
		}
	}
	j.st.Routes = append(j.st.Routes, journalRoute{dst, ifname})
	j.save()
	return nil
}

func (j *Journal) DelRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	err := j.Configurator.DelRoute(ctx, dst, ifname)
	j.mu.Lock()
	defer j.mu.Unlock()
	for i, r := range j.st.Routes {
		if r.Dst == dst && r.Iface == ifname {
			j.st.Routes = append(j.st.Routes[:i], j.st.Routes[i+1:]...)
			break
		}
	}
	j.save()
	return err
}

func (j *Journal) AddBypass(ctx context.Context, host netip.Addr) error {
	if err := j.Configurator.AddBypass(ctx, host); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, h := range j.st.Bypass {
		if h == host {
			return nil
		}
	}
	j.st.Bypass = append(j.st.Bypass, host)
	j.save()
	return nil
}

func (j *Journal) DelBypass(ctx context.Context, host netip.Addr) error {
	err := j.Configurator.DelBypass(ctx, host)
	j.mu.Lock()
	defer j.mu.Unlock()
	for i, h := range j.st.Bypass {
		if h == host {
			j.st.Bypass = append(j.st.Bypass[:i], j.st.Bypass[i+1:]...)
			break
		}
	}
	j.save()
	return err
}

func (j *Journal) SetNAT(ctx context.Context, pool netip.Prefix, dsts []netip.Prefix, ifname string) error {
	if err := j.Configurator.SetNAT(ctx, pool, dsts, ifname); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(dsts) == 0 {
		j.st.NAT = ""
	} else {
		j.st.NAT = ifname
	}
	j.save()
	return nil
}
