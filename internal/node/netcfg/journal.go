package netcfg

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/safefile"
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
	// Log, when set, hears what went wrong with the file itself: a record
	// that could not be written is a change to the host that a crash would
	// leave behind, and nobody should learn that only then.
	Log *slog.Logger

	mu sync.Mutex
	st journalState
}

func (j *Journal) log() *slog.Logger {
	if j.Log != nil {
		return j.Log
	}
	return slog.Default()
}

type journalRoute struct {
	Dst   netip.Prefix `json:"dst"`
	Iface string       `json:"iface"`
}

type journalState struct {
	Routes []journalRoute `json:"routes,omitempty"`
	Bypass []netip.Addr   `json:"bypass,omitempty"`
	NAT    string         `json:"nat_iface,omitempty"`
	// Arrival: ReplyViaArrival is on for this device
	Arrival string `json:"arrival_iface,omitempty"`
	// DNS: the host's resolver points at the hub's resolvers for this
	// device. It usually dies with the device, but not when the device
	// outlives the process (a crash before the TUN was closed).
	DNS string `json:"dns_iface,omitempty"`
}

// Watch passes on to the wrapped configurator when it can watch the network.
func (j *Journal) Watch(ctx context.Context, changed func()) bool {
	if w, ok := j.Configurator.(Watcher); ok {
		return w.Watch(ctx, changed)
	}
	return false
}

// NewJournal journals c into path (created 0600 next to the node's state).
func NewJournal(c Configurator, path string) *Journal {
	return &Journal{Configurator: c, path: path}
}

// Recover undoes what a previous process left behind and returns how many
// entries it removed. The resolver goes first: a host still pointed at a
// resolver inside a tunnel that is gone resolves no name at all, and on
// macOS not even its own resolver answers any more (R144).
//
// What a removal says is taken seriously. One that answered -- including "no
// such route", the usual case after the device went with the process -- is
// done. One that never answered keeps its record, so the next start, or
// `boundgate-node -repair`, tries again instead of forgetting it.
func (j *Journal) Recover(ctx context.Context) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	// only a journal this process wrote: under privilege separation the
	// directory belongs to the worker, which must not dictate what root
	// removes (safefile)
	b, err := safefile.ReadOwn(j.path, 1<<20)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return 0
	case errors.Is(err, safefile.ErrNotOwn):
		// something else under the journal's name: the worker's doing, in
		// a directory that is this process's (R145). It goes, so that the
		// next record can be written; what it hid cannot be recovered
		removed, rerr := safefile.Reclaim(j.path)
		j.log().Error("THE NETWORK JOURNAL'S NAME WAS TAKEN BY SOMETHING ELSE: host changes of a previous process may still be there (`ip route`, `nft list ruleset`)", "path", j.path, "err", err, "removed", removed, "remove_err", rerr)
		return 0
	case err != nil:
		j.log().Error("the network journal cannot be read; host changes of a previous process may still be there", "path", j.path, "err", err)
		return 0
	}
	var old journalState
	if json.Unmarshal(b, &old) != nil {
		_ = os.Remove(j.path)
		return 0
	}
	n, kept := 0, journalState{}
	if l, ok := j.Configurator.(LinkDNSConfigurator); ok && old.DNS != "" {
		if err := giveBackDNS(ctx, l, old.DNS); err != nil {
			kept.DNS = old.DNS
		}
		n++
	}
	if a, ok := j.Configurator.(ArrivalRouter); ok && old.Arrival != "" {
		octx, cancel := opContext(ctx)
		err := a.ReplyViaArrival(octx, old.Arrival, false) // also flushes the tunnel's table
		if cutOff(octx, err) {
			kept.Arrival = old.Arrival
		}
		cancel()
		n++
	}
	for _, r := range old.Routes {
		octx, cancel := opContext(ctx)
		if cutOff(octx, j.Configurator.DelRoute(octx, r.Dst, r.Iface)) {
			kept.Routes = append(kept.Routes, r)
		}
		cancel()
		n++
	}
	for _, h := range old.Bypass {
		octx, cancel := opContext(ctx)
		if cutOff(octx, j.Configurator.DelBypass(octx, h)) {
			kept.Bypass = append(kept.Bypass, h)
		}
		cancel()
		n++
	}
	if old.NAT != "" {
		octx, cancel := opContext(ctx)
		if cutOff(octx, j.Configurator.SetNAT(octx, netip.Prefix{}, nil, old.NAT)) {
			kept.NAT = old.NAT
		}
		cancel()
		n++
	}
	j.st = kept
	j.save() // removes the file when nothing is left over
	return n
}

// opContext is how long one change to the host's network may take here. Each
// gets its own deadline: a command that hangs -- `route delete` on a device
// that has just gone does, for seconds -- must not eat the time of what
// follows it, least of all the resolver.
func opContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}

// cutOff says the command never answered (its deadline or the caller cut it
// off), so whether it took effect is unknown and its record has to stay.
func cutOff(ctx context.Context, err error) bool { return err != nil && ctx.Err() != nil }

// giveBackDNS points the host back at its own resolver, with three tries of
// their own: this is the one host change that, left behind, takes the whole
// machine's name resolution with it.
func giveBackDNS(ctx context.Context, l LinkDNSConfigurator, ifname string) error {
	var err error
	for try := 0; try < 3; try++ {
		octx, cancel := opContext(ctx)
		err = l.SetLinkDNS(octx, ifname, nil)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return err
}

// save writes the state; called with mu held.
func (j *Journal) save() {
	if len(j.st.Routes) == 0 && len(j.st.Bypass) == 0 && j.st.NAT == "" && j.st.Arrival == "" && j.st.DNS == "" {
		if _, err := safefile.Reclaim(j.path); err != nil {
			j.log().Error("the network journal could not be removed", "path", j.path, "err", err)
		}
		if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			j.log().Error("the network journal could not be removed", "path", j.path, "err", err)
		}
		return
	}
	b, _ := json.MarshalIndent(j.st, "", "  ")
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		j.log().Error("THE NETWORK JOURNAL CANNOT BE WRITTEN: a crash would leave this process's host changes behind", "path", j.path, "err", err)
		return
	}
	// whatever else has taken the name since the last record goes first:
	// the directory is this process's, and the rename below would fail on a
	// directory under the name (R145)
	if removed, err := safefile.Reclaim(j.path); err != nil {
		j.log().Error("THE NETWORK JOURNAL CANNOT BE WRITTEN: a crash would leave this process's host changes behind", "path", j.path, "err", err)
		return
	} else if removed {
		j.log().Warn("the network journal's name was taken by something else; removed it", "path", j.path)
	}
	if err := safefile.WriteAtomic(j.path, b); err != nil {
		j.log().Error("THE NETWORK JOURNAL CANNOT BE WRITTEN: a crash would leave this process's host changes behind", "path", j.path, "err", err)
	}
}

// HasBypass reports whether host is a bypass route this journal recorded:
// what the parent of privilege separation lets a worker remove again.
func (j *Journal) HasBypass(host netip.Addr) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, h := range j.st.Bypass {
		if h == host {
			return true
		}
	}
	return false
}

func (j *Journal) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	return j.Configurator.CreateTUN(name, mtu)
}

// An addition is recorded when it succeeded and also when its command never
// answered (cutOff): it may have taken effect all the same, and a record of
// a change that is not there costs nothing -- its removal answers "no such
// route" and counts as done -- while a change without a record outlives a
// crash. A command that answered with an error changed nothing.
func (j *Journal) AddRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	err := j.Configurator.AddRoute(ctx, dst, ifname)
	if err != nil && !cutOff(ctx, err) {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, r := range j.st.Routes {
		if r.Dst == dst && r.Iface == ifname {
			return err
		}
	}
	j.st.Routes = append(j.st.Routes, journalRoute{dst, ifname})
	j.save()
	return err
}

func (j *Journal) DelRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	err := j.Configurator.DelRoute(ctx, dst, ifname)
	j.mu.Lock()
	defer j.mu.Unlock()
	if cutOff(ctx, err) {
		return err // never answered: the route may still be there, so its record stays
	}
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
	err := j.Configurator.AddBypass(ctx, host)
	if err != nil && !cutOff(ctx, err) {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, h := range j.st.Bypass {
		if h == host {
			return err
		}
	}
	j.st.Bypass = append(j.st.Bypass, host)
	j.save()
	return err
}

func (j *Journal) DelBypass(ctx context.Context, host netip.Addr) error {
	err := j.Configurator.DelBypass(ctx, host)
	j.mu.Lock()
	defer j.mu.Unlock()
	if cutOff(ctx, err) {
		return err // never answered: the host route may still be there
	}
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
	err := j.Configurator.SetNAT(ctx, pool, dsts, ifname)
	j.mu.Lock()
	defer j.mu.Unlock()
	switch {
	case len(dsts) > 0 && (err == nil || cutOff(ctx, err)):
		j.st.NAT = ifname
	case len(dsts) == 0 && err == nil:
		j.st.NAT = ""
	default:
		return err // nothing changed, or a removal that may not have happened
	}
	j.save()
	return err
}

// ReplyViaArrival passes on to the wrapped configurator (ArrivalRouter) and
// records it, so that a crashed daemon's rules are removed on the next start.
// SetLinkDNS passes on to the wrapped configurator (LinkDNSConfigurator) and
// records which device the host's resolver was pointed at. Journal implements
// it on every platform so that the record is kept; netcfg.LinkDNS says
// whether the platform underneath can really do it.
func (j *Journal) SetLinkDNS(ctx context.Context, ifname string, servers []netip.Addr) error {
	l, ok := j.Configurator.(LinkDNSConfigurator)
	if !ok {
		return errors.New("netcfg: this platform's daemon keeps the system's resolver")
	}
	err := l.SetLinkDNS(ctx, ifname, servers)
	j.mu.Lock()
	defer j.mu.Unlock()
	switch {
	case err != nil && len(servers) == 0:
		// The removal failed, so the host is still pointed at a resolver
		// in the tunnel. This record is then the only way back -- and
		// without it a machine whose daemon is gone resolves no name at
		// all until someone reboots it (R144). Measured on 2026-10-22.
		return err
	case len(servers) > 0 && (err == nil || cutOff(ctx, err)):
		j.st.DNS = ifname
	case len(servers) == 0:
		j.st.DNS = ""
	}
	j.save()
	return err
}

func (j *Journal) ReplyViaArrival(ctx context.Context, ifname string, on bool) error {
	a, ok := j.Configurator.(ArrivalRouter)
	if !ok {
		return errors.New("netcfg: reply_via_arrival is only available on Linux")
	}
	err := a.ReplyViaArrival(ctx, ifname, on)
	j.mu.Lock()
	defer j.mu.Unlock()
	if cutOff(ctx, err) {
		if on && j.st.Arrival != ifname {
			j.st.Arrival = ifname // it may be there all the same
			j.save()
		}
		return err // never answered: the rule may still be there
	}
	if on && err == nil {
		j.st.Arrival = ifname
	} else if !on {
		j.st.Arrival = ""
	}
	j.save()
	return err
}
