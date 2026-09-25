// Package snapshot turns the database into versioned registry.Snapshots,
// one view per node, and lets long-poll handlers wait for the next version.
package snapshot

import (
	"context"
	"strings"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Source builds snapshots and broadcasts version changes.
type Source struct {
	db *db.DB

	mu      sync.Mutex
	version uint64
	waiters []chan struct{}
	// cache of the global node list per version; per-node views are cheap
	// to derive from it
	cachedVersion uint64
	cachedNodes   []registry.Node
	cachedSess    []registry.Session
	cachedPol     []db.Policy
	cachedLists   []db.List
	cachedNet     db.NetworkSettings
	cachedAt      time.Time
	cachedChain   []registry.SignerLink
}

// New creates a source. Call Notify after every mutation that bumped the
// database version (handlers do this via the returned version).
func New(d *db.DB) *Source { return &Source{db: d} }

type loaded struct {
	version  uint64
	nodes    []registry.Node
	sessions []registry.Session
	policies []db.Policy
	lists    []db.List
	net      db.NetworkSettings
	at       time.Time
	chain    []registry.SignerLink
}

func (s *Source) load(ctx context.Context) (loaded, error) {
	version, err := s.db.SnapshotVersion(ctx)
	if err != nil {
		return loaded{}, err
	}
	s.mu.Lock()
	if s.cachedNodes != nil && s.cachedVersion == version {
		l := loaded{version, s.cachedNodes, s.cachedSess, s.cachedPol, s.cachedLists, s.cachedNet, s.cachedAt, s.cachedChain}
		s.mu.Unlock()
		return l, nil
	}
	s.mu.Unlock()

	rows, err := s.db.ApprovedNodes(ctx)
	if err != nil {
		return loaded{}, err
	}
	net, err := s.db.Network(ctx)
	if err != nil {
		return loaded{}, err
	}
	sessRows, err := s.db.ActiveSessions(ctx)
	if err != nil {
		return loaded{}, err
	}
	policies, err := s.db.EnabledPolicies(ctx)
	if err != nil {
		return loaded{}, err
	}
	lists, err := s.db.Lists(ctx)
	if err != nil {
		return loaded{}, err
	}
	// The signed admin key list travels with every snapshot, exactly as
	// stored: nodes verify it themselves (binding.VerifyChain).
	chain, err := s.db.SignerLinks(ctx)
	if err != nil {
		return loaded{}, err
	}
	nodes := make([]registry.Node, 0, len(rows))
	for _, n := range rows {
		nodes = append(nodes, toRegistry(n))
	}
	sessions := make([]registry.Session, 0, len(sessRows))
	for _, se := range sessRows {
		groups := se.Groups
		if groups == nil {
			groups = []string{}
		}
		sessions = append(sessions, registry.Session{ID: se.ID, NodeID: transport.DeviceID(se.NodeID), Subject: se.Subject, Email: se.Email, Username: se.Username, Groups: groups, ExpiresAt: se.ExpiresAt})
	}
	at := time.Now().UTC()
	s.mu.Lock()
	s.cachedVersion, s.cachedNodes, s.cachedSess, s.cachedPol, s.cachedLists, s.cachedNet, s.cachedAt, s.cachedChain = version, nodes, sessions, policies, lists, net, at, chain
	s.mu.Unlock()
	return loaded{version, nodes, sessions, policies, lists, net, at, chain}, nil
}

func toRegistry(n db.Node) registry.Node {
	out := registry.Node{
		ID:            transport.DeviceID(n.ID),
		Name:          n.Name,
		SPKI:          n.SPKI,
		Platform:      n.Platform,
		KeyKind:       n.KeyKind,
		HardwareBound: n.HardwareBound,
		Kind:          n.Kind,
		Roles:         n.Roles,
		OverlayIP:     n.OverlayIP,
		Prefixes:      n.Prefixes,
		Tags:          n.Tags,
		ApprovedAt:    n.ApprovedAt,
		KeyVersion:    n.KeyVersion,
		Binding:       n.Binding,
		Signature:     n.Signature,
		SignedBy:      n.SignedBy,
	}
	// hubs are dialed there by every spoke; a spoke with an address can be
	// dialed by its peers instead of being reached through a relay (M7)
	out.PublicAddr = n.PublicAddr
	if out.Roles == nil {
		out.Roles = []registry.Role{}
	}
	return out
}

// BuildFor creates the snapshot as node self sees it: its own record,
// every other approved node as a peer, the active user sessions of itself
// and its peers, the enabled policies scoped to it and the lists those
// policies name. An empty self yields the global view for admins (every
// policy, every list).
//
// Sessions go to every node: any node can be the receiving end of a hub
// tunnel, a direct path or a relayed one (PATHS.md), and it decides a
// connection by the user behind the peer (groups, subject, email) and
// refuses an interactive peer without a session. Which peer will connect
// is not known in advance (R123).
func (s *Source) BuildFor(ctx context.Context, self transport.DeviceID) (*registry.Snapshot, error) {
	l, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	snap := &registry.Snapshot{
		Version:       l.version,
		GeneratedAt:   l.at,
		MaxAgeSeconds: l.net.MaxAgeSeconds,
		Peers:         make([]registry.Node, 0, len(l.nodes)),
		Sessions:      make([]registry.Session, 0, len(l.sessions)),
		Policies:      make([]registry.Policy, 0, len(l.policies)),
		Pool:          l.net.Pool,
		SignerChain:   l.chain,
	}
	for _, p := range l.policies {
		if self == "" || p.AppliesTo(string(self)) {
			snap.Policies = append(snap.Policies, registry.Policy{ID: p.ID, Name: p.Name, Cedar: p.Cedar})
		}
	}
	// a node gets the lists its policies name, nothing else: a list is the
	// organisation's data (internal hosts, partners' addresses), and a node
	// that decides nothing by it has no use for it
	for _, x := range l.lists {
		if self != "" && !namesList(snap.Policies, x.Name) {
			continue
		}
		snap.Lists = append(snap.Lists, registry.List{Name: x.Name, Kind: x.Kind, Entries: x.Entries})
	}
	known := make(map[transport.DeviceID]bool, len(l.nodes))
	for _, n := range l.nodes {
		known[n.ID] = true
		if n.ID == self {
			snap.Self = n
			continue
		}
		snap.Peers = append(snap.Peers, n)
	}
	for _, se := range l.sessions {
		if known[se.NodeID] {
			snap.Sessions = append(snap.Sessions, se)
		}
	}
	snap.Index()
	return snap, nil
}

// namesList reports whether one of the policies refers to the list. List
// names are lowercase letters, digits and . _ -, so the reference is
// always spelled the same way (db.ListRef).
func namesList(ps []registry.Policy, name string) bool {
	ref := db.ListRef(name)
	for _, p := range ps {
		if strings.Contains(p.Cedar, ref) {
			return true
		}
	}
	return false
}

// Notify wakes every long-poll waiter. Call it after the database version
// changed.
func (s *Source) Notify(version uint64) {
	s.mu.Lock()
	if version > s.version {
		s.version = version
	}
	ws := s.waiters
	s.waiters = nil
	s.mu.Unlock()
	for _, w := range ws {
		close(w)
	}
}

// Wait blocks until the version exceeds since, the timeout passes, or ctx
// ends. It returns true when a newer version is available.
func (s *Source) Wait(ctx context.Context, since uint64, timeout time.Duration) (bool, error) {
	cur, err := s.db.SnapshotVersion(ctx)
	if err != nil {
		return false, err
	}
	if cur > since {
		return true, nil
	}
	ch := make(chan struct{})
	s.mu.Lock()
	s.waiters = append(s.waiters, ch)
	s.mu.Unlock()
	select {
	case <-ch:
		return true, nil
	case <-time.After(timeout):
		s.remove(ch)
		cur, err := s.db.SnapshotVersion(ctx)
		return err == nil && cur > since, err
	case <-ctx.Done():
		s.remove(ch)
		return false, ctx.Err()
	}
}

func (s *Source) remove(ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, w := range s.waiters {
		if w == ch {
			s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
			return
		}
	}
}
