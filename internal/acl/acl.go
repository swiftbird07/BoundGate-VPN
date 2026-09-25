// Package acl evaluates Cedar policies for overlay flows. It is the only
// place that turns registry state (nodes, sessions, prefixes) into Cedar
// entities and the only caller of the Cedar authorizer, on nodes (per new
// flow) and in the control plane (validation, dry runs).
//
// Cedar's decision model is used unchanged: a flow is allowed when at least
// one permit policy matches and no forbid policy matches; with no policies
// everything is denied. Policies come from the control plane inside the
// snapshot; a node never loads policy text from anywhere else.
//
// Entity model (see docs/ACL.md):
//
//	BoundGate::Node::"<node id>"      the originating node (principal) or an owner of the destination
//	BoundGate::User::"<subject>"      parent of a node with an active user session
//	BoundGate::Group::"<name>"        parents of a user (OIDC groups)
//	BoundGate::Role::"<role>"         parents of a node (granted roles)
//	BoundGate::Host::"<ip>"           the destination (resource) of one flow
//	BoundGate::Network::"<prefix>"    parents of a host: the pool and every announced prefix containing it
//	BoundGate::Action::"connect"      the only action
package acl

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Entity types and the action.
const (
	TypeNode    types.EntityType = "BoundGate::Node"
	TypeUser    types.EntityType = "BoundGate::User"
	TypeGroup   types.EntityType = "BoundGate::Group"
	TypeRole    types.EntityType = "BoundGate::Role"
	TypeTag     types.EntityType = "BoundGate::Tag"
	TypeHost    types.EntityType = "BoundGate::Host"
	TypeNetwork types.EntityType = "BoundGate::Network"
	TypeList    types.EntityType = "BoundGate::List"
	TypeAction  types.EntityType = "BoundGate::Action"

	ActionConnect = "connect"
)

// MaxPolicyBytes bounds one policy document.
const MaxPolicyBytes = 64 << 10

// PolicyError is a policy the engine could not compile; it is skipped.
type PolicyError struct {
	ID   string
	Name string
	Err  error
}

func (e PolicyError) Error() string { return fmt.Sprintf("policy %s (%s): %v", e.Name, e.ID, e.Err) }

// Validate parses a policy document (one or more Cedar statements) and
// returns the first syntax error.
func Validate(cedarText string) error {
	if len(cedarText) > MaxPolicyBytes {
		return fmt.Errorf("acl: policy longer than %d bytes", MaxPolicyBytes)
	}
	if strings.TrimSpace(cedarText) == "" {
		return errors.New("acl: empty policy")
	}
	_, err := cedar.NewPolicyListFromBytes("policy", []byte(cedarText))
	return err
}

// Request is one flow to decide.
type Request struct {
	// Principal is the node the flow originates from (the tunnel peer on a
	// hub; the owner of the source address on a router).
	Principal transport.DeviceID
	Dst       netip.Addr
	Port      uint16
	Proto     uint8
	// SNI is the TLS server name of the first ClientHello, if known.
	SNI string
	// DNSName is the queried name for DNS flows, if known.
	DNSName string
	// Resolved are the names this principal recently resolved to Dst
	// (dnsmap). They match lists of kind "dynamic" and are readable in a
	// policy as resource.resolved_names.
	Resolved []string
	Now      time.Time
}

// Decision is the outcome.
type Decision struct {
	Allow bool
	// Policies are the determining policies (names), Reasons their ids.
	Policies []string
	Reasons  []string
	// Errors are evaluation errors (a policy referenced a missing attribute).
	Errors []string
	// Session is the principal's user session used for the decision, if any.
	Session *registry.Session
	// Owner is the node that owns the destination, if any.
	Owner *registry.Node
	// PermitBySNI: denied without a server name, but some permit in scope
	// looks at `sni`: the flow table lets the TCP handshake through and
	// decides again on the ClientHello (or aborts the connection).
	PermitBySNI bool
}

// Engine is a compiled policy set plus the entities of one snapshot.
type Engine struct {
	snap     *registry.Snapshot
	set      *cedar.PolicySet
	names    map[string]string // policy id -> name
	base     types.EntityMap
	networks []network
	errs     []PolicyError
	count    int
	// permitsBySNI: at least one permit statement reads `sni`, or names a
	// list of server names
	permitsBySNI bool
	// permitsDynamic: at least one permit statement names a dynamic list,
	// whose server-name fallback applies to public addresses only
	permitsDynamic bool
	lists          []list
	// internal is what the overlay itself reaches: the pool and every
	// network a node announces (default routes aside)
	internal []netip.Prefix
}

// sniAttr finds a policy that reads the server name: resource.sni,
// context.sni, `has sni`, ["sni"].
var sniAttr = regexp.MustCompile(`\.sni\b|\bhas\s+sni\b|\["sni"\]`)

// list is a compiled registry.List: a destination is `in` the list when
// its address is inside one of the prefixes (kind ip), or its DNS query
// name or TLS server name matches one of the names (kind dns, sni).
//
// Kind "dynamic" is the access list that follows the traffic: it holds
// names and addresses together, and a name matches however the node sees
// it — as the DNS question, as the TLS server name, or as a name this
// principal resolved to the destination a moment ago (dnsmap). Its address
// entries may carry a port or a port range.
//
// A name "*.example.com" matches every name under example.com, not
// example.com itself.
type list struct {
	name     string
	kind     string
	uid      types.EntityUID
	prefixes []netip.Prefix
	addrs    []registry.AddrEntry // kind dynamic
	exact    map[string]bool
	under    []string // "*.example.com" stored as ".example.com"
}

func compileList(l registry.List) list {
	c := list{name: l.Name, kind: l.Kind, uid: types.NewEntityUID(TypeList, types.String(l.Name)), exact: map[string]bool{}}
	for _, e := range l.Entries {
		if l.Kind == "ip" {
			if p, err := netip.ParsePrefix(e); err == nil {
				c.prefixes = append(c.prefixes, p)
			}
			continue
		}
		if l.Kind == "dynamic" {
			if a, ok, err := registry.ParseAddrEntry(e); ok && err == nil {
				c.addrs = append(c.addrs, a)
				continue
			}
		}
		e = strings.ToLower(e)
		if rest, ok := strings.CutPrefix(e, "*."); ok {
			c.under = append(c.under, "."+rest)
		} else {
			c.exact[e] = true
		}
	}
	return c
}

// has reports whether the flow's destination is in the list. sniFallback
// says whether a dynamic list may match by the TLS server name alone
// (Engine.sniFallback).
func (c *list) has(r Request, sniFallback bool) bool {
	switch c.kind {
	case "ip":
		for _, p := range c.prefixes {
			if p.Contains(r.Dst) {
				return true
			}
		}
		return false
	case "sni":
		return c.hasName(r.SNI)
	case "dns":
		return c.hasName(r.DNSName)
	case "dynamic":
		for _, a := range c.addrs {
			if a.Matches(r.Dst, r.Port) {
				return true
			}
		}
		if c.hasName(r.DNSName) || sniFallback && c.hasName(r.SNI) {
			return true
		}
		for _, n := range r.Resolved {
			if c.hasName(n) {
				return true
			}
		}
	}
	return false
}

func (c *list) hasName(name string) bool {
	if name == "" {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if c.exact[name] {
		return true
	}
	for _, u := range c.under {
		if strings.HasSuffix(name, u) && len(name) > len(u) {
			return true
		}
	}
	return false
}

type network struct {
	prefix netip.Prefix
	owners []transport.DeviceID
	uid    types.EntityUID
}

// New compiles the snapshot's policies and builds the entities. Policies
// that fail to compile are skipped and reported by Errors; the rest still
// apply (Cedar default: nothing matches, nothing is allowed).
func New(snap *registry.Snapshot) *Engine {
	e := &Engine{snap: snap, set: cedar.NewPolicySet(), names: make(map[string]string), base: types.EntityMap{}}
	if snap == nil {
		return e
	}
	sniLists, dynamicLists := map[string]bool{}, map[string]bool{}
	for _, l := range snap.Lists {
		c := compileList(l)
		e.lists = append(e.lists, c)
		e.base[c.uid] = types.Entity{UID: c.uid, Attributes: types.NewRecord(types.RecordMap{"kind": types.String(l.Kind), "name": types.String(l.Name)})}
		switch l.Kind {
		case "sni":
			sniLists[`BoundGate::List::"`+l.Name+`"`] = true
		case "dynamic":
			// a dynamic list matches the server name too (of a public
			// address), so a permit that names one is worth waiting for the
			// ClientHello
			dynamicLists[`BoundGate::List::"`+l.Name+`"`] = true
		}
	}
	for _, p := range snap.Policies {
		if len(p.Cedar) > MaxPolicyBytes {
			e.errs = append(e.errs, PolicyError{p.ID, p.Name, errors.New("policy too long")})
			continue
		}
		list, err := cedar.NewPolicyListFromBytes(p.Name, []byte(p.Cedar))
		if err != nil {
			e.errs = append(e.errs, PolicyError{p.ID, p.Name, err})
			continue
		}
		for i, pol := range list {
			id := p.ID
			if len(list) > 1 {
				id = p.ID + "#" + strconv.Itoa(i)
			}
			e.set.Add(types.PolicyID(id), pol)
			e.names[id] = p.Name
			e.count++
			if pol.Effect() == cedar.Permit {
				text := pol.MarshalCedar()
				if sniAttr.Match(text) {
					e.permitsBySNI = true
				}
				for ref := range sniLists {
					if bytes.Contains(text, []byte(ref)) {
						e.permitsBySNI = true
					}
				}
				for ref := range dynamicLists {
					if bytes.Contains(text, []byte(ref)) {
						e.permitsDynamic = true
					}
				}
			}
		}
	}
	e.buildEntities()
	return e
}

// Policies returns the number of compiled policy statements.
func (e *Engine) Policies() int { return e.count }

// Errors lists the policies that did not compile.
func (e *Engine) Errors() []PolicyError { return e.errs }

// LearnsNames reports whether any list of kind "dynamic" is in the
// snapshot: without one there is nothing to learn from DNS answers.
func (e *Engine) LearnsNames() bool {
	for i := range e.lists {
		if e.lists[i].kind == "dynamic" {
			return true
		}
	}
	return false
}

// Learns reports whether a list of kind "dynamic" holds this name. A node
// remembers the addresses of an answer only for such a name: everything
// else would fill the cache without a policy ever asking for it.
func (e *Engine) Learns(name string) bool {
	for i := range e.lists {
		if e.lists[i].kind == "dynamic" && e.lists[i].hasName(name) {
			return true
		}
	}
	return false
}

func (e *Engine) buildEntities() {
	s := e.snap
	nodes := append([]registry.Node{s.Self}, s.Peers...)
	roles := map[registry.Role]bool{}
	groups := map[string]bool{}
	byPrefix := map[netip.Prefix]*network{}
	addNet := func(p netip.Prefix, owner transport.DeviceID) {
		p = p.Masked()
		n := byPrefix[p]
		if n == nil {
			n = &network{prefix: p, uid: types.NewEntityUID(TypeNetwork, types.String(p.String()))}
			byPrefix[p] = n
			e.networks = append(e.networks, *n)
		}
		if owner != "" {
			n.owners = append(n.owners, owner)
		}
	}
	if s.Pool.IsValid() {
		addNet(s.Pool, "")
		e.internal = append(e.internal, s.Pool.Masked())
	}
	for _, n := range nodes {
		if n.ID == "" {
			continue
		}
		for _, r := range n.Roles {
			roles[r] = true
		}
		for _, t := range n.Tags {
			uid := types.NewEntityUID(TypeTag, types.String(t))
			e.base[uid] = types.Entity{UID: uid}
		}
		for _, p := range n.Prefixes {
			addNet(p.Prefix, n.ID)
			if p.Prefix.Bits() > 0 {
				e.internal = append(e.internal, p.Prefix.Masked())
			}
		}
		e.base[nodeUID(n.ID)] = e.nodeEntity(n, nil)
	}
	for _, se := range s.Sessions {
		uid := types.NewEntityUID(TypeUser, types.String(se.Subject))
		parents := make([]types.EntityUID, 0, len(se.Groups))
		gs := make([]types.Value, 0, len(se.Groups))
		for _, g := range se.Groups {
			groups[g] = true
			parents = append(parents, types.NewEntityUID(TypeGroup, types.String(g)))
			gs = append(gs, types.String(g))
		}
		e.base[uid] = types.Entity{UID: uid, Parents: types.NewEntityUIDSet(parents...), Attributes: types.NewRecord(types.RecordMap{
			"subject": types.String(se.Subject), "email": types.String(se.Email), "username": types.String(se.Username), "groups": types.NewSet(gs...),
		})}
	}
	for r := range roles {
		uid := types.NewEntityUID(TypeRole, types.String(r))
		e.base[uid] = types.Entity{UID: uid}
	}
	for g := range groups {
		uid := types.NewEntityUID(TypeGroup, types.String(g))
		e.base[uid] = types.Entity{UID: uid}
	}
	// rebuild the slice with the final owner lists, longest prefix first
	e.networks = e.networks[:0]
	for _, n := range byPrefix {
		e.networks = append(e.networks, *n)
	}
	sort.Slice(e.networks, func(i, j int) bool {
		if e.networks[i].prefix.Bits() != e.networks[j].prefix.Bits() {
			return e.networks[i].prefix.Bits() > e.networks[j].prefix.Bits()
		}
		return e.networks[i].prefix.String() < e.networks[j].prefix.String()
	})
	for _, n := range e.networks {
		parents := make([]types.EntityUID, 0, len(n.owners))
		for _, o := range n.owners {
			parents = append(parents, nodeUID(o))
		}
		e.base[n.uid] = types.Entity{UID: n.uid, Parents: types.NewEntityUIDSet(parents...), Attributes: types.NewRecord(types.RecordMap{
			"prefix": types.IPAddr(n.prefix),
		})}
	}
	e.base[actionUID()] = types.Entity{UID: actionUID()}
}

func nodeUID(id transport.DeviceID) types.EntityUID {
	return types.NewEntityUID(TypeNode, types.String(id))
}

func actionUID() types.EntityUID { return types.NewEntityUID(TypeAction, ActionConnect) }

func (e *Engine) nodeEntity(n registry.Node, se *registry.Session) types.Entity {
	parents := make([]types.EntityUID, 0, len(n.Roles)+1)
	rs := make([]types.Value, 0, len(n.Roles))
	for _, r := range n.Roles {
		parents = append(parents, types.NewEntityUID(TypeRole, types.String(r)))
		rs = append(rs, types.String(r))
	}
	if se != nil {
		parents = append(parents, types.NewEntityUID(TypeUser, types.String(se.Subject)))
	}
	tags := make([]types.Value, 0, len(n.Tags))
	for _, t := range n.Tags {
		// a parent as well: `principal in BoundGate::Tag::"laptop"`, and for destinations
		// `resource in BoundGate::Tag::"production"` (host in network in the tagged node)
		parents = append(parents, types.NewEntityUID(TypeTag, types.String(t)))
		tags = append(tags, types.String(t))
	}
	attrs := types.RecordMap{
		"tags":           types.NewSet(tags...),
		"name":           types.String(n.Name),
		"kind":           types.String(n.Kind),
		"roles":          types.NewSet(rs...),
		"hardware_bound": types.Boolean(n.HardwareBound),
		"platform":       types.String(n.Platform),
		"key_kind":       types.String(n.KeyKind),
		"has_session":    types.Boolean(se != nil),
	}
	if n.OverlayIP.IsValid() {
		attrs["overlay_ip"] = types.IPAddr(netip.PrefixFrom(n.OverlayIP, n.OverlayIP.BitLen()))
	}
	return types.Entity{UID: nodeUID(n.ID), Parents: types.NewEntityUIDSet(parents...), Attributes: types.NewRecord(attrs)}
}

// Owner returns the node that owns addr: the node with that overlay
// address, else the announcer of the longest prefix containing it. With
// several announcers (HA routers) the first in snapshot order wins.
func Owner(s *registry.Snapshot, addr netip.Addr) (registry.Node, bool) {
	if s == nil {
		return registry.Node{}, false
	}
	nodes := append([]registry.Node{s.Self}, s.Peers...)
	for _, n := range nodes {
		if n.ID != "" && n.OverlayIP == addr {
			return n, true
		}
	}
	var best registry.Node
	bits := -1
	for _, n := range nodes {
		for _, p := range n.Prefixes {
			if p.Prefix.Contains(addr) && p.Prefix.Bits() > bits {
				best, bits = n, p.Prefix.Bits()
			}
		}
	}
	return best, bits >= 0
}

// ProtoName names an IP protocol number the way policies see it.
func ProtoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	}
	return strconv.Itoa(int(p))
}

// layered lets a request add its ephemeral entities (the principal with
// its current session, the destination host) on top of the snapshot's.
type layered struct {
	top, base types.EntityMap
}

func (l layered) Get(uid types.EntityUID) (types.Entity, bool) {
	if ent, ok := l.top[uid]; ok {
		return ent, true
	}
	return l.base.Get(uid)
}

// Evaluate decides one flow. An unknown principal is denied without
// consulting the policies.
func (e *Engine) Evaluate(r Request) Decision {
	d := e.evaluate(r)
	if !d.Allow && r.SNI == "" && r.Proto == 6 && (e.permitsBySNI || e.permitsDynamic && e.sniFallback(r.Dst)) {
		d.PermitBySNI = true
	}
	return d
}

// sniFallback reports whether a dynamic list may match a connection to dst
// by its TLS server name alone, without a resolution the node saw. Only for
// a public address: the name in a ClientHello is whatever the client writes
// there, so inside the overlay, in a network a node announces or in any
// private range it would open every TLS service to anyone who can type a
// permitted name. There, a name counts only when the node saw it resolve to
// the address (Request.Resolved), or an address entry names it.
func (e *Engine) sniFallback(dst netip.Addr) bool {
	dst = dst.Unmap()
	if !dst.IsGlobalUnicast() || dst.IsPrivate() || !publicV4(dst) {
		return false
	}
	for _, p := range e.internal {
		if p.Contains(dst) {
			return false
		}
	}
	return true
}

// nonPublicV4 are IPv4 ranges IsPrivate leaves out that are not the
// internet either.
var nonPublicV4 = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved
}

func publicV4(a netip.Addr) bool {
	for _, p := range nonPublicV4 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func (e *Engine) evaluate(r Request) Decision {
	var d Decision
	if e.snap == nil {
		return d
	}
	var pn registry.Node
	switch {
	case r.Principal == e.snap.Self.ID && r.Principal != "":
		pn = e.snap.Self
	default:
		n, ok := e.snap.Peer(r.Principal)
		if !ok {
			return d
		}
		pn = n
	}
	now := r.Now
	if now.IsZero() {
		now = time.Now()
	}
	var se *registry.Session
	if s, ok := e.snap.SessionFor(pn.ID, now); ok {
		se = &s
		d.Session = se
	}
	top := types.EntityMap{}
	top[nodeUID(pn.ID)] = e.nodeEntity(pn, se)

	hostUID := types.NewEntityUID(TypeHost, types.String(r.Dst.String()))
	var parents []types.EntityUID
	for _, n := range e.networks {
		if n.prefix.Contains(r.Dst) {
			parents = append(parents, n.uid)
		}
	}
	if owner, ok := Owner(e.snap, r.Dst); ok {
		d.Owner = &owner
		parents = append(parents, nodeUID(owner.ID))
	}
	sniFallback := r.SNI != "" && e.sniFallback(r.Dst)
	for i := range e.lists {
		if e.lists[i].has(r, sniFallback) {
			parents = append(parents, e.lists[i].uid)
		}
	}
	proto := ProtoName(r.Proto)
	hostAttrs := types.RecordMap{
		"ip":       types.IPAddr(netip.PrefixFrom(r.Dst, r.Dst.BitLen())),
		"port":     types.Long(r.Port),
		"protocol": types.String(proto),
	}
	ctx := types.RecordMap{
		"protocol":    types.String(proto),
		"port":        types.Long(r.Port),
		"has_session": types.Boolean(se != nil),
	}
	if r.SNI != "" {
		hostAttrs["sni"] = types.String(r.SNI)
		ctx["sni"] = types.String(r.SNI)
	}
	if r.DNSName != "" {
		hostAttrs["dns_name"] = types.String(r.DNSName)
		ctx["dns_name"] = types.String(r.DNSName)
	}
	if len(r.Resolved) > 0 {
		ns := make([]types.Value, 0, len(r.Resolved))
		for _, n := range r.Resolved {
			ns = append(ns, types.String(n))
		}
		hostAttrs["resolved_names"] = types.NewSet(ns...)
		ctx["resolved_names"] = types.NewSet(ns...)
	}
	if se != nil {
		gs := make([]types.Value, 0, len(se.Groups))
		for _, g := range se.Groups {
			gs = append(gs, types.String(g))
		}
		ctx["user"] = types.NewRecord(types.RecordMap{
			"subject": types.String(se.Subject), "username": types.String(se.Username), "email": types.String(se.Email), "groups": types.NewSet(gs...),
		})
	}
	top[hostUID] = types.Entity{UID: hostUID, Parents: types.NewEntityUIDSet(parents...), Attributes: types.NewRecord(hostAttrs)}
	if e.count == 0 {
		return d // nothing permits: denied, but the context is still useful
	}

	decision, diag := cedar.Authorize(e.set, layered{top: top, base: e.base}, types.Request{
		Principal: nodeUID(pn.ID),
		Action:    actionUID(),
		Resource:  hostUID,
		Context:   types.NewRecord(ctx),
	})
	d.Allow = decision == types.Allow
	for _, rs := range diag.Reasons {
		id := string(rs.PolicyID)
		d.Reasons = append(d.Reasons, id)
		d.Policies = append(d.Policies, e.names[id])
	}
	for _, de := range diag.Errors {
		d.Errors = append(d.Errors, fmt.Sprintf("%s: %s", e.names[string(de.PolicyID)], de.Message))
	}
	sort.Strings(d.Reasons)
	sort.Strings(d.Policies)
	return d
}
