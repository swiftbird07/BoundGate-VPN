// Package registry holds a node's view of the overlay: who it is, which peers
// are approved (with their keys, roles, overlay addresses and announced
// prefixes), which hubs to dial, which user sessions exist and the overlay
// pool. The control plane produces one versioned Snapshot per node; the node
// swaps it atomically and reacts to the Diff (revocation, hub changes).
//
// The SPKI lookup path is part of the security TCB: transport consults it
// during every TLS handshake. A missing snapshot means "nobody is approved".
package registry

import (
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Role is what a node is allowed to do. Roles are granted by an admin and
// are part of the signed binding; a node cannot choose them.
type Role string

const (
	// RoleEndpoint is an interactive or workload node that reaches things.
	RoleEndpoint Role = "endpoint"
	// RoleSubnetRouter announces prefixes behind the node.
	RoleSubnetRouter Role = "subnet-router"
	// RoleHub accepts tunnels from other nodes and routes between them.
	RoleHub Role = "hub"
	// RoleExitNode announces 0.0.0.0/0 (a subnet router for the internet).
	RoleExitNode Role = "exit-node"
)

// AllRoles lists the known roles.
var AllRoles = []Role{RoleEndpoint, RoleSubnetRouter, RoleHub, RoleExitNode}

// ParseRoles validates role names.
func ParseRoles(names []string) ([]Role, error) {
	out := make([]Role, 0, len(names))
	for _, n := range names {
		r := Role(n)
		if !slices.Contains(AllRoles, r) {
			return nil, fmt.Errorf("registry: unknown role %q", n)
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// HasRole reports whether r is in roles.
func HasRole(roles []Role, r Role) bool { return slices.Contains(roles, r) }

// Kind is the identity kind of a node: an interactive node is used by a
// person and needs a user session (OIDC login) before hubs admit it; a
// workload (server, router, hub) is admitted on its device identity alone.
// Kind is granted by an admin and part of the signed binding.
type Kind string

const (
	KindInteractive Kind = "interactive"
	KindWorkload    Kind = "workload"
)

// ParseKind validates a kind; empty means interactive.
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case "", KindInteractive:
		return KindInteractive, nil
	case KindWorkload:
		return KindWorkload, nil
	default:
		return "", fmt.Errorf("registry: unknown kind %q (interactive or workload)", s)
	}
}

// NeedsSession reports whether hubs require a user session for the node.
func (n Node) NeedsSession() bool { return n.Kind != KindWorkload }

// PrefixMode says how a subnet router forwards traffic into a prefix.
type PrefixMode string

const (
	// ModeRouted forwards packets unchanged; the network behind the router
	// needs a route back to the overlay pool.
	ModeRouted PrefixMode = "routed"
	// ModeSNAT masquerades overlay sources behind the router's own address.
	ModeSNAT PrefixMode = "snat"
)

// Prefix is one announced network of a node.
type Prefix struct {
	Prefix netip.Prefix `json:"prefix"`
	Mode   PrefixMode   `json:"mode"`
}

// Validate checks a prefix entry.
func (p Prefix) Validate() error {
	if !p.Prefix.IsValid() || !p.Prefix.Addr().Is4() {
		return fmt.Errorf("registry: prefix %q must be IPv4", p.Prefix)
	}
	switch p.Mode {
	case ModeRouted, ModeSNAT:
		return nil
	default:
		return fmt.Errorf("registry: prefix %s: mode must be routed or snat", p.Prefix)
	}
}

// Node is an approved node as every peer sees it.
type Node struct {
	ID            transport.DeviceID `json:"id"`
	Name          string             `json:"name"`
	SPKI          devicekey.SPKIHash `json:"spki"`
	Platform      string             `json:"platform,omitempty"`
	KeyKind       string             `json:"key_kind,omitempty"`
	HardwareBound bool               `json:"hardware_bound"`
	Kind          Kind               `json:"kind"`
	Roles         []Role             `json:"roles"`
	OverlayIP     netip.Addr         `json:"overlay_ip"`
	Prefixes      []Prefix           `json:"prefixes,omitempty"`
	// PublicAddr is host:port of the tunnel listener; hubs only. It is not
	// part of the signed binding: a wrong address only fails the pinned
	// handshake.
	PublicAddr string    `json:"public_addr,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`
	// KeyVersion counts re-keys of the same node id; part of the binding.
	KeyVersion int `json:"key_version"`
	// Binding is the canonical JSON an admin signed (package binding) and
	// Signature the armored SSHSIG over it. Nodes verify both against the
	// admin keys pinned at enrollment and ignore peers that fail.
	Binding   string `json:"binding,omitempty"`
	Signature string `json:"signature,omitempty"`
	// SignedBy is the fingerprint of the signing admin key (informational).
	SignedBy string `json:"signed_by,omitempty"`
}

// IsHub reports whether the node accepts tunnels.
func (n Node) IsHub() bool { return HasRole(n.Roles, RoleHub) && n.PublicAddr != "" }

// Session is an active user session bound to a node.
type Session struct {
	ID        string             `json:"id"`
	NodeID    transport.DeviceID `json:"node_id"`
	Subject   string             `json:"subject"`
	Email     string             `json:"email,omitempty"`
	Username  string             `json:"username,omitempty"`
	Groups    []string           `json:"groups"`
	ExpiresAt time.Time          `json:"expires_at"`
}

// Policy is one Cedar policy document.
type Policy struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Cedar string `json:"cedar"`
}

// Snapshot is an immutable, versioned registry state for one node.
type Snapshot struct {
	Version     uint64    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	// MaxAgeSeconds says how long a node may keep enforcing with this
	// snapshot when the control plane is unreachable; afterwards it fails
	// closed. 0 means the default (see DefaultMaxAge).
	MaxAgeSeconds int `json:"max_age_seconds,omitempty"`
	// Self is the receiving node's own record.
	Self Node `json:"self"`
	// Peers are the other approved nodes this node may talk to.
	Peers    []Node    `json:"peers"`
	Sessions []Session `json:"sessions,omitempty"`
	Policies []Policy  `json:"policies,omitempty"`
	// Pool is the overlay address range.
	Pool netip.Prefix `json:"pool"`

	bySPKI map[devicekey.SPKIHash]*Node
	byID   map[transport.DeviceID]*Node
	sessBy map[transport.DeviceID]*Session
}

// DefaultMaxAge is used when the snapshot carries no MaxAgeSeconds.
const DefaultMaxAge = 24 * time.Hour

// MaxAge returns the snapshot's grace period.
func (s *Snapshot) MaxAge() time.Duration {
	if s == nil || s.MaxAgeSeconds <= 0 {
		return DefaultMaxAge
	}
	return time.Duration(s.MaxAgeSeconds) * time.Second
}

// Index builds the lookup maps. It is called by Holder.Store; call it
// yourself if you construct a Snapshot by hand.
func (s *Snapshot) Index() {
	s.bySPKI = make(map[devicekey.SPKIHash]*Node, len(s.Peers))
	s.byID = make(map[transport.DeviceID]*Node, len(s.Peers))
	for i := range s.Peers {
		n := &s.Peers[i]
		s.bySPKI[n.SPKI] = n
		s.byID[n.ID] = n
	}
	s.sessBy = make(map[transport.DeviceID]*Session, len(s.Sessions))
	for i := range s.Sessions {
		se := &s.Sessions[i]
		s.sessBy[se.NodeID] = se
	}
}

// LookupSPKI implements transport.DeviceLookup for one snapshot: only peers
// are admitted, never the node itself.
func (s *Snapshot) LookupSPKI(h devicekey.SPKIHash) (transport.DeviceInfo, bool) {
	if s == nil || s.bySPKI == nil {
		return transport.DeviceInfo{}, false
	}
	n, ok := s.bySPKI[h]
	if !ok {
		return transport.DeviceInfo{}, false
	}
	return transport.DeviceInfo{ID: n.ID, HardwareBound: n.HardwareBound}, true
}

// Peer returns the peer record by ID.
func (s *Snapshot) Peer(id transport.DeviceID) (Node, bool) {
	if s == nil || s.byID == nil {
		return Node{}, false
	}
	n, ok := s.byID[id]
	if !ok {
		return Node{}, false
	}
	return *n, true
}

// Hubs returns the peers that accept tunnels, in snapshot order.
func (s *Snapshot) Hubs() []Node {
	if s == nil {
		return nil
	}
	var out []Node
	for _, n := range s.Peers {
		if n.IsHub() {
			out = append(out, n)
		}
	}
	return out
}

// SessionFor returns the active, unexpired session of a node.
func (s *Snapshot) SessionFor(id transport.DeviceID, now time.Time) (Session, bool) {
	if s == nil || s.sessBy == nil {
		return Session{}, false
	}
	se, ok := s.sessBy[id]
	if !ok || !now.Before(se.ExpiresAt) {
		return Session{}, false
	}
	return *se, true
}

// Diff describes what changed between two snapshots, as far as a node must
// react to it.
type Diff struct {
	// RemovedPeers lost approval or changed key/roles/addresses; any tunnel
	// with them must be closed (they reconnect with the new configuration).
	RemovedPeers []transport.DeviceID
	AddedPeers   []transport.DeviceID
	// RemovedSessions lists nodes whose session disappeared or changed.
	RemovedSessions []transport.DeviceID
	// SessionsChanged is true when any session (own or peer) was added,
	// removed or replaced.
	SessionsChanged bool
	HubsChanged     bool
	SelfChanged     bool
	PoliciesChanged bool
	PoolChanged     bool
}

// Holder publishes the current snapshot to concurrent readers.
type Holder struct {
	p       atomic.Pointer[Snapshot]
	fetched atomic.Int64 // unix nanos of the last successful fetch
}

// Load returns the current snapshot or nil.
func (h *Holder) Load() *Snapshot { return h.p.Load() }

// Store indexes and installs s and returns the diff against the previous one.
func (h *Holder) Store(s *Snapshot) Diff {
	s.Index()
	old := h.p.Swap(s)
	h.fetched.Store(time.Now().UnixNano())
	return diff(old, s)
}

// Touch records that the control plane confirmed the current version is
// still current (a long-poll that timed out without changes).
func (h *Holder) Touch() { h.fetched.Store(time.Now().UnixNano()) }

// Clear forgets the snapshot: nobody is approved until the next Store. Used
// when the control plane withdraws the node's own approval.
func (h *Holder) Clear() { h.p.Store(nil) }

// Stale reports whether the snapshot is older than its MaxAge, i.e. the
// control plane has been unreachable for too long. Enforcement points must
// fail closed then.
func (h *Holder) Stale(now time.Time) bool {
	s := h.p.Load()
	if s == nil {
		return true
	}
	return now.Sub(time.Unix(0, h.fetched.Load())) > s.MaxAge()
}

// LookupSPKI implements transport.DeviceLookup against the current snapshot.
// No snapshot, or a stale one, means no approved peers (fail closed).
func (h *Holder) LookupSPKI(k devicekey.SPKIHash) (transport.DeviceInfo, bool) {
	if h.Stale(time.Now()) {
		return transport.DeviceInfo{}, false
	}
	return h.p.Load().LookupSPKI(k)
}

func diff(old, cur *Snapshot) Diff {
	var d Diff
	if old == nil {
		for _, n := range cur.Peers {
			d.AddedPeers = append(d.AddedPeers, n.ID)
		}
		d.HubsChanged, d.SelfChanged, d.PoliciesChanged, d.PoolChanged = true, true, true, true
		d.SessionsChanged = len(cur.Sessions) > 0
		return d
	}
	for id := range old.byID {
		if _, ok := cur.byID[id]; !ok {
			d.RemovedPeers = append(d.RemovedPeers, id)
		}
	}
	for id, n := range cur.byID {
		if o, ok := old.byID[id]; !ok {
			d.AddedPeers = append(d.AddedPeers, id)
		} else if !sameNode(*o, *n) {
			// key or configuration changed: the old tunnel is invalid
			d.RemovedPeers = append(d.RemovedPeers, id)
			d.AddedPeers = append(d.AddedPeers, id)
		}
	}
	for id, se := range old.sessBy {
		cs, ok := cur.sessBy[id]
		if !ok || cs.ID != se.ID {
			d.RemovedSessions = append(d.RemovedSessions, id)
			d.SessionsChanged = true
		}
	}
	for id, se := range cur.sessBy {
		if os, ok := old.sessBy[id]; !ok || os.ID != se.ID || !os.ExpiresAt.Equal(se.ExpiresAt) {
			d.SessionsChanged = true
		}
	}
	d.HubsChanged = !slices.EqualFunc(old.Hubs(), cur.Hubs(), sameNode)
	d.SelfChanged = !sameNode(old.Self, cur.Self)
	d.PoliciesChanged = !slices.Equal(old.Policies, cur.Policies)
	d.PoolChanged = old.Pool != cur.Pool
	return d
}

// sameNode compares everything a peer relies on. A re-signature with the
// same content is not a change.
func sameNode(a, b Node) bool {
	return a.ID == b.ID && a.SPKI == b.SPKI && a.KeyVersion == b.KeyVersion && a.Kind == b.Kind && a.OverlayIP == b.OverlayIP && a.PublicAddr == b.PublicAddr &&
		a.HardwareBound == b.HardwareBound && slices.Equal(a.Roles, b.Roles) && slices.Equal(a.Prefixes, b.Prefixes)
}

// Validate checks internal consistency.
func (s *Snapshot) Validate() error {
	if !s.Pool.IsValid() || !s.Pool.Addr().Is4() {
		return fmt.Errorf("registry: pool %q must be a valid IPv4 prefix", s.Pool)
	}
	seenKey := make(map[devicekey.SPKIHash]bool, len(s.Peers)+1)
	seenIP := make(map[netip.Addr]bool, len(s.Peers)+1)
	check := func(n Node) error {
		if n.ID == "" || n.SPKI.IsZero() {
			return fmt.Errorf("registry: node %q needs id and spki", n.ID)
		}
		if !n.OverlayIP.IsValid() || !s.Pool.Contains(n.OverlayIP) {
			return fmt.Errorf("registry: node %q: overlay ip %s not inside pool %s", n.ID, n.OverlayIP, s.Pool)
		}
		if seenKey[n.SPKI] {
			return fmt.Errorf("registry: duplicate spki for node %q", n.ID)
		}
		if seenIP[n.OverlayIP] {
			return fmt.Errorf("registry: duplicate overlay ip %s (node %q)", n.OverlayIP, n.ID)
		}
		seenKey[n.SPKI], seenIP[n.OverlayIP] = true, true
		for _, p := range n.Prefixes {
			if err := p.Validate(); err != nil {
				return fmt.Errorf("node %q: %w", n.ID, err)
			}
		}
		return nil
	}
	if s.Self.ID != "" {
		if err := check(s.Self); err != nil {
			return err
		}
	}
	for _, n := range s.Peers {
		if err := check(n); err != nil {
			return err
		}
	}
	return nil
}
