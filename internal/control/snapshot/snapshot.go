// Package snapshot turns the database into versioned registry.Snapshots,
// one view per node, and lets long-poll handlers wait for the next version.
package snapshot

import (
	"context"
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
	cachedNet     db.NetworkSettings
	cachedAt      time.Time
}

// New creates a source. Call Notify after every mutation that bumped the
// database version (handlers do this via the returned version).
func New(d *db.DB) *Source { return &Source{db: d} }

func (s *Source) load(ctx context.Context) (uint64, []registry.Node, db.NetworkSettings, time.Time, error) {
	version, err := s.db.SnapshotVersion(ctx)
	if err != nil {
		return 0, nil, db.NetworkSettings{}, time.Time{}, err
	}
	s.mu.Lock()
	if s.cachedNodes != nil && s.cachedVersion == version {
		nodes, net, at := s.cachedNodes, s.cachedNet, s.cachedAt
		s.mu.Unlock()
		return version, nodes, net, at, nil
	}
	s.mu.Unlock()

	rows, err := s.db.ApprovedNodes(ctx)
	if err != nil {
		return 0, nil, db.NetworkSettings{}, time.Time{}, err
	}
	net, err := s.db.Network(ctx)
	if err != nil {
		return 0, nil, db.NetworkSettings{}, time.Time{}, err
	}
	nodes := make([]registry.Node, 0, len(rows))
	for _, n := range rows {
		nodes = append(nodes, toRegistry(n))
	}
	at := time.Now().UTC()
	s.mu.Lock()
	s.cachedVersion, s.cachedNodes, s.cachedNet, s.cachedAt = version, nodes, net, at
	s.mu.Unlock()
	return version, nodes, net, at, nil
}

func toRegistry(n db.Node) registry.Node {
	out := registry.Node{
		ID:            transport.DeviceID(n.ID),
		Name:          n.Name,
		SPKI:          n.SPKI,
		Platform:      n.Platform,
		KeyKind:       n.KeyKind,
		HardwareBound: n.HardwareBound,
		Roles:         n.Roles,
		OverlayIP:     n.OverlayIP,
		Prefixes:      n.Prefixes,
		ApprovedAt:    n.ApprovedAt,
		KeyVersion:    n.KeyVersion,
		Binding:       n.Binding,
		Signature:     n.Signature,
		SignedBy:      n.SignedBy,
	}
	if registry.HasRole(n.Roles, registry.RoleHub) {
		out.PublicAddr = n.PublicAddr
	}
	if out.Roles == nil {
		out.Roles = []registry.Role{}
	}
	return out
}

// BuildFor creates the snapshot as node self sees it: its own record and
// every other approved node as a peer. An empty self yields the global view
// for admins (all nodes as peers).
//
// M3 narrows Peers and Policies to what the node is allowed to reach.
func (s *Source) BuildFor(ctx context.Context, self transport.DeviceID) (*registry.Snapshot, error) {
	version, nodes, net, at, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	snap := &registry.Snapshot{
		Version:       version,
		GeneratedAt:   at,
		MaxAgeSeconds: net.MaxAgeSeconds,
		Peers:         make([]registry.Node, 0, len(nodes)),
		Pool:          net.Pool,
	}
	for _, n := range nodes {
		if n.ID == self {
			snap.Self = n
			continue
		}
		snap.Peers = append(snap.Peers, n)
	}
	snap.Index()
	return snap, nil
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
