package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// resolverNet records what the daemon would do to the host's resolver.
type resolverNet struct {
	netcfg.Configurator
	set  []string // "bg0 10.20.0.1" or "bg0 off"
	fail error
}

func (r *resolverNet) SetLinkDNS(_ context.Context, ifname string, servers []netip.Addr) error {
	if r.fail != nil {
		return r.fail
	}
	if len(servers) == 0 {
		r.set = append(r.set, ifname+" off")
		return nil
	}
	line := ifname
	for _, s := range servers {
		line += " " + s.String()
	}
	r.set = append(r.set, line)
	return nil
}

func resolverSession(net netcfg.Configurator, mode string) (*Node, *session, *spokeManager) {
	n := &Node{net: net, log: slog.New(slog.DiscardHandler), cfg: Config{Resolver: mode}}
	s := &session{n: n, ifname: "bg0", self: registry.Node{ID: "nas"}}
	m := &spokeManager{s: s, installed: map[netip.Prefix]bool{}}
	s.spoke = m
	return n, s, m
}

// A daemon points the host's resolver at the hub's while the overlay is up,
// and says so in its status.
func TestTheHostsResolverFollowsTheHub(t *testing.T) {
	rec := &resolverNet{}
	_, s, m := resolverSession(rec, "")
	hub := netip.MustParseAddr("10.20.0.1")

	m.mu.Lock()
	m.applyDNSLocked(context.Background(), []netip.Addr{hub})
	m.mu.Unlock()
	if len(rec.set) != 1 || rec.set[0] != "bg0 10.20.0.1" {
		t.Fatalf("set %v", rec.set)
	}
	if !s.resolver {
		t.Error("the session does not remember that it changed the resolver")
	}
	if got, err := m.dnsState(); len(got) != 1 || got[0] != "10.20.0.1" || err != "" {
		t.Errorf("status %v %q", got, err)
	}

	// the way down gives it back
	m.mu.Lock()
	m.applyDNSLocked(context.Background(), nil)
	m.mu.Unlock()
	if len(rec.set) != 2 || rec.set[1] != "bg0 off" {
		t.Fatalf("set %v", rec.set)
	}
	if s.resolver {
		t.Error("the session still thinks it owns the resolver")
	}
	if got, _ := m.dnsState(); len(got) != 0 {
		t.Errorf("status still names resolvers: %v", got)
	}
}

// A host without systemd-resolved keeps its own resolver: the overlay comes
// up anyway, and the status says why names go elsewhere.
func TestWithoutAResolverTheNodeSaysSoAndCarriesOn(t *testing.T) {
	rec := &resolverNet{fail: errors.New("netcfg: no systemd-resolved on the system bus")}
	_, s, m := resolverSession(rec, "")
	m.mu.Lock()
	m.applyDNSLocked(context.Background(), []netip.Addr{netip.MustParseAddr("10.20.0.1")})
	m.mu.Unlock()
	if s.resolver {
		t.Error("it thinks it changed the resolver")
	}
	got, err := m.dnsState()
	if len(got) != 0 || err == "" {
		t.Fatalf("status %v %q", got, err)
	}
	if err != "netcfg: no systemd-resolved on the system bus" {
		t.Errorf("the reason was lost: %q", err)
	}
}

// resolver: system leaves the host alone, whatever the hub offers.
func TestResolverSystemLeavesTheHostAlone(t *testing.T) {
	rec := &resolverNet{}
	_, _, m := resolverSession(rec, ResolverSystem)
	m.primary = &hubLink{}
	m.mu.Lock()
	dns := m.resolversLocked()
	m.applyDNSLocked(context.Background(), dns)
	m.mu.Unlock()
	if len(dns) != 0 {
		t.Fatalf("resolvers %v", dns)
	}
	// the host was not touched at all, and nothing is reported as wrong
	if len(rec.set) != 0 {
		t.Fatalf("set %v", rec.set)
	}
	if got, err := m.dnsState(); len(got) != 0 || err != "" {
		t.Fatalf("status %v %q", got, err)
	}
}

// A platform whose daemon cannot do it yet (macOS, Windows) reports that
// instead of pretending the names go through the tunnel.
func TestAPlatformThatCannotSetTheResolverReportsIt(t *testing.T) {
	_, _, m := resolverSession(nil, "")
	m.mu.Lock()
	m.applyDNSLocked(context.Background(), []netip.Addr{netip.MustParseAddr("10.20.0.1")})
	m.mu.Unlock()
	got, err := m.dnsState()
	if len(got) != 0 || err == "" {
		t.Fatalf("status %v %q", got, err)
	}
}

// macOS asks the resolvers it was given and does not fall back to the
// machine's own: measured on 2026-10-22, a name took 61 s and then failed
// while the configured resolver was dead. So losing the hub must give the
// resolver back, or the host would keep asking an address that no longer
// goes anywhere.
func TestLosingThePrimaryHubGivesTheResolverBack(t *testing.T) {
	rec := &resolverNet{}
	_, s, m := resolverSession(rec, "")
	hub := netip.MustParseAddr("10.20.0.1")

	m.mu.Lock()
	m.applyDNSLocked(context.Background(), []netip.Addr{hub})
	m.mu.Unlock()
	if !s.resolver {
		t.Fatal("the resolver was not set in the first place")
	}

	// the hub is still in the list, but its tunnel is gone: that is what
	// the link loop leaves behind before it dials again
	m.primary = &hubLink{}
	m.mu.Lock()
	dns := m.resolversLocked()
	m.applyDNSLocked(context.Background(), dns)
	m.mu.Unlock()
	if len(dns) != 0 {
		t.Fatalf("resolvers of a hub without a tunnel: %v", dns)
	}
	if len(rec.set) != 2 || rec.set[1] != "bg0 off" {
		t.Fatalf("set %v, want the resolver given back", rec.set)
	}
	if s.resolver {
		t.Error("the session still thinks it owns the resolver")
	}
	if got, err := m.dnsState(); len(got) != 0 || err != "" {
		t.Errorf("status %v %q", got, err)
	}
}
