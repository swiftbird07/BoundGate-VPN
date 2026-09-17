package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// Node status values.
const (
	StatusPending   = "pending"
	StatusConfirmed = "confirmed" // M1.6: admin confirmed, signature outstanding
	StatusApproved  = "approved"
	StatusRevoked   = "revoked"
)

// Node is a row of the nodes table.
type Node struct {
	ID            string
	Name          string
	Hostname      string
	Platform      string
	KeyKind       string
	HardwareBound bool
	SPKI          devicekey.SPKIHash
	CertDER       []byte
	Attrs         map[string]string
	// Requested* are claims from the enrollment request.
	RequestedRoles    []registry.Role
	RequestedPrefixes []registry.Prefix
	// Granted by an admin.
	Kind       registry.Kind
	Roles      []registry.Role
	Prefixes   []registry.Prefix
	OverlayIP  netip.Addr
	PublicAddr string

	// Binding is the canonical JSON that was signed, Signature the SSHSIG.
	KeyVersion int
	Binding    string
	Signature  string
	SignedBy   string // signer fingerprint
	SignedAt   time.Time

	Status              string
	RequestedAt         time.Time
	RequestIP           string
	ConfirmedAt         time.Time
	ConfirmedBy         string
	ApprovedAt          time.Time
	ApprovedBy          string
	RevokedAt           time.Time
	RevokedBy           string
	LastSeenAt          time.Time
	LastSnapshotVersion uint64
	ActiveTunnels       int
}

const nodeCols = `id, name, hostname, platform, key_kind, hardware_bound, spki_hash, cert_der, attrs_json,
	requested_roles_json, requested_prefixes_json, roles_json, prefixes_json, overlay_ip, public_addr,
	status, requested_at, request_ip, confirmed_at, confirmed_by, approved_at, approved_by, revoked_at, revoked_by,
	last_seen_at, last_snapshot_version, active_tunnels, key_version, binding_json, binding_sig, signed_by, signed_at, kind`

type scanner interface{ Scan(dest ...any) error }

func scanNode(s scanner) (Node, error) {
	var n Node
	var spki []byte
	var attrs, reqRoles, reqPrefixes, roles, prefixes, overlay, requestedAt string
	var confirmedAt, confirmedBy, approvedAt, approvedBy, revokedAt, revokedBy, lastSeen, signedAt sql.NullString
	if err := s.Scan(&n.ID, &n.Name, &n.Hostname, &n.Platform, &n.KeyKind, &n.HardwareBound, &spki, &n.CertDER, &attrs,
		&reqRoles, &reqPrefixes, &roles, &prefixes, &overlay, &n.PublicAddr,
		&n.Status, &requestedAt, &n.RequestIP, &confirmedAt, &confirmedBy, &approvedAt, &approvedBy, &revokedAt, &revokedBy,
		&lastSeen, &n.LastSnapshotVersion, &n.ActiveTunnels, &n.KeyVersion, &n.Binding, &n.Signature, &n.SignedBy, &signedAt, &n.Kind); err != nil {
		return n, err
	}
	n.SignedAt = parseTime(signedAt)
	copy(n.SPKI[:], spki)
	_ = json.Unmarshal([]byte(attrs), &n.Attrs)
	_ = json.Unmarshal([]byte(reqRoles), &n.RequestedRoles)
	_ = json.Unmarshal([]byte(reqPrefixes), &n.RequestedPrefixes)
	_ = json.Unmarshal([]byte(roles), &n.Roles)
	_ = json.Unmarshal([]byte(prefixes), &n.Prefixes)
	if overlay != "" {
		n.OverlayIP, _ = netip.ParseAddr(overlay)
	}
	n.RequestedAt = parseTime(sql.NullString{String: requestedAt, Valid: true})
	n.ConfirmedAt, n.ConfirmedBy = parseTime(confirmedAt), confirmedBy.String
	n.ApprovedAt, n.ApprovedBy = parseTime(approvedAt), approvedBy.String
	n.RevokedAt, n.RevokedBy = parseTime(revokedAt), revokedBy.String
	n.LastSeenAt = parseTime(lastSeen)
	return n, nil
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	if string(b) == "null" {
		return "[]"
	}
	return string(b)
}

// EnrollRequest is what a node sends.
type EnrollRequest struct {
	Name          string
	Hostname      string
	Platform      string
	KeyKind       string
	HardwareBound bool
	SPKI          devicekey.SPKIHash
	CertDER       []byte
	RequestIP     string
	Roles         []registry.Role
	Prefixes      []registry.Prefix
	PublicAddr    string
}

// CreatePending records an enrollment request. A key that is already known
// (any status) is a conflict: the node must ask for its status instead.
func (d *DB) CreatePending(ctx context.Context, r EnrollRequest) (Node, error) {
	id := NewID()
	name := strings.TrimSpace(r.Name)
	if name == "" {
		name = r.Hostname
	}
	if name == "" {
		name = "node-" + id[:8]
	}
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO nodes (id, name, hostname, platform, key_kind, hardware_bound, spki_hash, cert_der, attrs_json,
			requested_roles_json, requested_prefixes_json, public_addr, status, requested_at, request_ip)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, 'pending', ?, ?)`,
			id, name, r.Hostname, r.Platform, r.KeyKind, r.HardwareBound, r.SPKI[:], r.CertDER,
			jsonOf(r.Roles), jsonOf(r.Prefixes), r.PublicAddr, now(), r.RequestIP)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return err
	})
	if err != nil {
		return Node{}, err
	}
	return d.NodeByID(ctx, id)
}

// NodeByID fetches one node.
func (d *DB) NodeByID(ctx context.Context, id string) (Node, error) {
	row := d.sql.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id)
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// NodeBySPKI fetches one node by key hash.
func (d *DB) NodeBySPKI(ctx context.Context, h devicekey.SPKIHash) (Node, error) {
	row := d.sql.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE spki_hash = ?`, h[:])
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// ListNodes returns nodes, optionally filtered by status, oldest request first
// for pending and by name otherwise.
func (d *DB) ListNodes(ctx context.Context, status string) ([]Node, error) {
	q := `SELECT ` + nodeCols + ` FROM nodes`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY name, requested_at`
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ApprovedNodes returns the nodes that belong in registry snapshots:
// approved and carrying a signature.
func (d *DB) ApprovedNodes(ctx context.Context) ([]Node, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE status = 'approved' AND binding_sig <> '' ORDER BY name, requested_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Grant is what an admin decides about a node.
type Grant struct {
	Name       string        // optional rename
	Kind       registry.Kind // "" keeps the current kind (new nodes: interactive)
	Roles      []registry.Role
	Prefixes   []registry.Prefix
	OverlayIP  netip.Addr // zero = assign the next free address
	PublicAddr string     // hubs; empty keeps what the node requested
}

// Validate checks the grant against the pool.
func (g Grant) Validate(pool netip.Prefix) error {
	if len(g.Roles) == 0 {
		return errors.New("at least one role is required")
	}
	if _, err := registry.ParseKind(string(g.Kind)); err != nil {
		return err
	}
	for _, p := range g.Prefixes {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	if len(g.Prefixes) > 0 && !registry.HasRole(g.Roles, registry.RoleSubnetRouter) && !registry.HasRole(g.Roles, registry.RoleExitNode) {
		return errors.New("prefixes need the subnet-router or exit-node role")
	}
	if g.OverlayIP.IsValid() && !pool.Contains(g.OverlayIP) {
		return fmt.Errorf("overlay ip %s is outside the pool %s", g.OverlayIP, pool)
	}
	return nil
}

// ConfirmNode records the admin's grant for a pending (or already
// confirmed) node and assigns the overlay address if none is set yet. The
// node stays out of snapshots until an admin key signed its binding
// (ApproveSigned). Nothing is bumped here.
func (d *DB) ConfirmNode(ctx context.Context, id, by string, g Grant, pool netip.Prefix) error {
	if err := g.Validate(pool); err != nil {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		cur, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.Status != StatusPending && cur.Status != StatusConfirmed {
			return fmt.Errorf("%w: node is %s", ErrConflict, cur.Status)
		}
		ip := g.OverlayIP
		if !ip.IsValid() {
			ip = cur.OverlayIP
		}
		if !ip.IsValid() || !pool.Contains(ip) {
			if ip, err = nextFreeOverlay(ctx, tx, pool); err != nil {
				return err
			}
		}
		kind := g.Kind
		if kind == "" {
			kind = cur.Kind
		}
		if kind == "" {
			kind = registry.KindInteractive
		}
		res, err := tx.ExecContext(ctx, `UPDATE nodes SET status = 'confirmed', confirmed_at = ?, confirmed_by = ?,
			name = COALESCE(NULLIF(?, ''), name), kind = ?, roles_json = ?, prefixes_json = ?, overlay_ip = ?,
			public_addr = COALESCE(NULLIF(?, ''), public_addr), binding_json = '', binding_sig = '', signed_by = '', signed_at = NULL
			WHERE id = ? AND status IN ('pending', 'confirmed')`,
			now(), by, g.Name, string(kind), jsonOf(g.Roles), jsonOf(g.Prefixes), ip.String(), g.PublicAddr, id)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: overlay ip %s is already taken", ErrConflict, ip)
			}
			return err
		}
		return affected(res)
	})
	return err
}

// ApproveSigned stores the verified signature of a confirmed node, marks the
// token used, moves the node to approved and bumps the snapshot. The caller
// has verified the signature against the current grant.
func (d *DB) ApproveSigned(ctx context.Context, id, token, bindingJSON, signature, signedBy string) (uint64, error) {
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE sign_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL`, now(), HashToken(token))
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return fmt.Errorf("%w: sign token", ErrTokenUsed)
		}
		res, err = tx.ExecContext(ctx, `UPDATE nodes SET status = 'approved', approved_at = ?, approved_by = ?,
			binding_json = ?, binding_sig = ?, signed_by = ?, signed_at = ?
			WHERE id = ? AND status = 'confirmed'`, now(), signedBy, bindingJSON, signature, signedBy, now(), id)
		if err != nil {
			return err
		}
		return affected(res)
	})
}

// UpdateNode changes the grant (or the name) of a node. For an approved
// node a change to a signed field (roles, prefixes, overlay address) drops
// the signature: the node goes back to confirmed, leaves the snapshots and
// needs a new signature. A name or public-address change keeps the
// approval and only bumps the snapshot. Returns the version and whether the
// node was demoted.
func (d *DB) UpdateNode(ctx context.Context, id string, g Grant, pool netip.Prefix) (uint64, bool, error) {
	cur, err := d.NodeByID(ctx, id)
	if err != nil {
		return 0, false, err
	}
	if g.Roles == nil {
		g.Roles = cur.Roles
	}
	if g.Prefixes == nil {
		g.Prefixes = cur.Prefixes
	}
	if !g.OverlayIP.IsValid() {
		g.OverlayIP = cur.OverlayIP
	}
	if g.PublicAddr == "" {
		g.PublicAddr = cur.PublicAddr
	}
	if g.Kind == "" {
		g.Kind = cur.Kind
	}
	if cur.Status == StatusApproved || cur.Status == StatusConfirmed {
		if err := g.Validate(pool); err != nil {
			return 0, false, fmt.Errorf("%w: %v", ErrConflict, err)
		}
	}
	signedChanged := !equalRoles(g.Roles, cur.Roles) || !equalPrefixes(g.Prefixes, cur.Prefixes) || g.OverlayIP != cur.OverlayIP || g.Kind != cur.Kind
	demote := cur.Status == StatusApproved && signedChanged
	bump := cur.Status == StatusApproved
	version, err := d.tx(ctx, bump, func(tx *sql.Tx) error {
		overlay := ""
		if g.OverlayIP.IsValid() {
			overlay = g.OverlayIP.String()
		}
		q := `UPDATE nodes SET name = COALESCE(NULLIF(?, ''), name), kind = ?, roles_json = ?, prefixes_json = ?, overlay_ip = ?, public_addr = ?`
		if demote {
			q += `, status = 'confirmed', binding_json = '', binding_sig = '', signed_by = '', signed_at = NULL, approved_at = NULL, approved_by = NULL`
		}
		res, err := tx.ExecContext(ctx, q+` WHERE id = ?`, g.Name, string(g.Kind), jsonOf(g.Roles), jsonOf(g.Prefixes), overlay, g.PublicAddr, id)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: overlay ip %s is already taken", ErrConflict, g.OverlayIP)
			}
			return err
		}
		return affected(res)
	})
	return version, demote, err
}

func equalRoles(a, b []registry.Role) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !registry.HasRole(b, r) {
			return false
		}
	}
	return true
}

func equalPrefixes(a, b []registry.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for _, p := range a {
		found := false
		for _, q := range b {
			if p.Prefix.Masked() == q.Prefix.Masked() && p.Mode == q.Mode {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// nextFreeOverlay returns the lowest unused host address in pool.
func nextFreeOverlay(ctx context.Context, tx *sql.Tx, pool netip.Prefix) (netip.Addr, error) {
	rows, err := tx.QueryContext(ctx, `SELECT overlay_ip FROM nodes WHERE overlay_ip <> ''`)
	if err != nil {
		return netip.Addr{}, err
	}
	defer rows.Close()
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return netip.Addr{}, err
		}
		if a, err := netip.ParseAddr(s); err == nil {
			used[a] = true
		}
	}
	pool = pool.Masked()
	for a := pool.Addr().Next(); pool.Contains(a); a = a.Next() {
		if !used[a] && a != broadcast(pool) {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: overlay pool %s exhausted", ErrConflict, pool)
}

func broadcast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		a[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom4(a)
}

// RejectNode deletes a pending or confirmed request.
func (d *DB) RejectNode(ctx context.Context, id string) error {
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE id = ? AND status IN ('pending', 'confirmed')`, id)
		if err != nil {
			return err
		}
		return affected(res)
	})
	return err
}

// RevokeNode unenrolls an approved node and bumps the snapshot. The row
// stays for the audit trail; the key can never be re-approved (a new
// enrollment needs a new key, which is the point). The overlay address is
// freed.
func (d *DB) RevokeNode(ctx context.Context, id, by string) (uint64, error) {
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE nodes SET status = 'revoked', revoked_at = ?, revoked_by = ?, overlay_ip = '' WHERE id = ? AND status = 'approved'`, now(), by, id)
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return err
		}
		// a revoked node has no user any more
		_, err = tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = ?, revoked_by = ?, end_reason = 'node revoked' WHERE node_id = ? AND revoked_at IS NULL`, now(), by, id)
		return err
	})
}

// TouchNode records that the node talked to us.
func (d *DB) TouchNode(ctx context.Context, id string) {
	_, _ = d.sql.ExecContext(ctx, `UPDATE nodes SET last_seen_at = ? WHERE id = ?`, now(), id)
}

// Heartbeat records liveness, the snapshot version a node runs and its
// tunnel count.
func (d *DB) Heartbeat(ctx context.Context, id string, version uint64, tunnels int) {
	_, _ = d.sql.ExecContext(ctx, `UPDATE nodes SET last_seen_at = ?, last_snapshot_version = ?, active_tunnels = ? WHERE id = ?`, now(), version, tunnels, id)
}

// ExpirePending deletes pending requests older than maxAge and returns how many.
func (d *DB) ExpirePending(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(timeFormat)
	res, err := d.sql.ExecContext(ctx, `DELETE FROM nodes WHERE status = 'pending' AND requested_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func affected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: no row in the expected state", ErrNotFound)
	}
	return nil
}
