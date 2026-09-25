package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Setting keys.
const (
	SettingNetwork        = "network"
	SettingBootstrapToken = "bootstrap_token" // {"hash": base64}
)

// NetworkSettings define the overlay pool. Every approved node gets one
// stable address from it. Changing the pool after nodes are approved is
// refused unless every assigned address still fits.
type NetworkSettings struct {
	Pool netip.Prefix `json:"pool"`
	// MaxAgeSeconds is how long nodes keep enforcing with a snapshot they
	// cannot refresh (0 = registry default).
	MaxAgeSeconds int `json:"max_age_seconds,omitempty"`
}

// DefaultNetwork is used until an admin sets something.
var DefaultNetwork = NetworkSettings{
	Pool: netip.MustParsePrefix("10.21.0.0/16"),
}

// privateRanges are where an overlay pool may lie: addresses no public
// destination has, so the overlay never shadows the internet.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space (CGNAT)
	netip.MustParsePrefix("fc00::/7"),      // unique local
}

// Validate checks the settings.
func (n NetworkSettings) Validate() error {
	if !n.Pool.IsValid() || !n.Pool.Addr().Is4() || n.Pool.Bits() > 30 || n.Pool.Bits() < 8 {
		return errors.New("pool must be an IPv4 prefix between /8 and /30")
	}
	if n.Pool.Masked() != n.Pool {
		return errors.New("pool must be a network address (host bits zero)")
	}
	private := false
	for _, r := range privateRanges {
		if r.Bits() <= n.Pool.Bits() && r.Contains(n.Pool.Addr()) {
			private = true
		}
	}
	if !private {
		return errors.New("pool must lie in a private range: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10")
	}
	if n.MaxAgeSeconds < 0 {
		return errors.New("max_age_seconds must not be negative")
	}
	return nil
}

// PrefixesInPool lists the node prefixes (confirmed and approved nodes)
// that overlap pool, as "name: prefix"; a default route never counts.
func PrefixesInPool(nodes []Node, pool netip.Prefix) []string {
	var out []string
	for _, n := range nodes {
		if n.Status != StatusConfirmed && n.Status != StatusApproved {
			continue
		}
		for _, p := range n.Prefixes {
			if prefixClearOfPool(p.Prefix, pool) != nil {
				out = append(out, n.Name+": "+p.Prefix.Masked().String())
			}
		}
	}
	return out
}

// GetSetting unmarshals a setting into v. Missing settings return ErrNotFound.
func (d *DB) GetSetting(ctx context.Context, key string, v any) error {
	var raw string
	err := d.sql.QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), v)
}

// PutSetting stores a setting. bump says whether gateways must learn about it.
func (d *DB) PutSetting(ctx context.Context, key string, v any, by string, bump bool) (uint64, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	return d.tx(ctx, bump, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			key, string(raw), now(), by)
		return err
	})
}

// Renumbered is a node that moved with the pool.
type Renumbered struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	From     netip.Addr `json:"from"`
	To       netip.Addr `json:"to"`
	Unsigned bool       `json:"needs_signature"` // was approved: its binding names the old address
}

// RenumberNetwork stores new network settings and moves every node whose
// overlay address is outside the new pool to the same host number inside it
// (10.21.0.7 in 10.21.0.0/16 becomes 10.25.0.7 in 10.25.0.0/16). The overlay
// address is part of the signed binding, so an approved node that moves goes
// back to confirmed, leaves the snapshots, and needs the administrator's
// signature again: the control plane cannot renumber anybody by itself. One
// transaction; nothing changes if any node does not fit.
func (d *DB) RenumberNetwork(ctx context.Context, n NetworkSettings, by string) (uint64, []Renumbered, error) {
	old, err := d.Network(ctx)
	if err != nil {
		return 0, nil, err
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return 0, nil, err
	}
	var moved []Renumbered
	version, err := d.tx(ctx, true, func(tx *sql.Tx) error {
		moved = nil
		rows, err := tx.QueryContext(ctx, `SELECT id, name, overlay_ip, status FROM nodes WHERE overlay_ip != '' AND status IN ('confirmed', 'approved') ORDER BY overlay_ip`)
		if err != nil {
			return err
		}
		type row struct{ id, name, ip, status string }
		var all []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.name, &r.ip, &r.status); err != nil {
				rows.Close()
				return err
			}
			all = append(all, r)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, r := range all {
			ip, err := netip.ParseAddr(r.ip)
			if err != nil || n.Pool.Contains(ip) {
				continue
			}
			to, err := sameHost(ip, old.Pool, n.Pool)
			if err != nil {
				return fmt.Errorf("%w: node %s (%s): %v", ErrConflict, r.name, ip, err)
			}
			moved = append(moved, Renumbered{ID: r.id, Name: r.name, From: ip, To: to, Unsigned: r.status == string(StatusApproved)})
		}
		// two passes: the new addresses may collide with old ones that are still to move
		for _, m := range moved {
			if _, err := tx.ExecContext(ctx, `UPDATE nodes SET overlay_ip = ? WHERE id = ?`, "moving:"+m.ID, m.ID); err != nil {
				return err
			}
		}
		for _, m := range moved {
			q := `UPDATE nodes SET overlay_ip = ?`
			if m.Unsigned {
				q += `, status = 'confirmed', binding_json = '', binding_sig = '', signed_by = '', signed_at = NULL, approved_at = NULL, approved_by = NULL`
			}
			if _, err := tx.ExecContext(ctx, q+` WHERE id = ?`, m.To.String(), m.ID); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					return fmt.Errorf("%w: %s, the new address of %s, is already taken", ErrConflict, m.To, m.Name)
				}
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			SettingNetwork, string(raw), now(), by)
		return err
	})
	return version, moved, err
}

// sameHost maps ip from pool `from` to the same host number in pool `to`.
func sameHost(ip netip.Addr, from, to netip.Prefix) (netip.Addr, error) {
	if !ip.Is4() || !from.Addr().Is4() || !to.Addr().Is4() {
		return netip.Addr{}, errors.New("only IPv4 pools can be renumbered")
	}
	num := func(a netip.Addr) uint32 {
		b := a.As4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	base := from.Masked().Addr()
	if !from.Contains(ip) {
		base = netip.PrefixFrom(ip, to.Bits()).Masked().Addr() // outside its old pool too: keep the host part as the new pool's size defines it
	}
	host := num(ip) - num(base)
	if to.Bits() < 32 && host >= 1<<(32-to.Bits())-1 || host == 0 {
		return netip.Addr{}, fmt.Errorf("host number %d does not fit into %s", host, to)
	}
	v := num(to.Masked().Addr()) + host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), nil
}

// Network returns the network settings or the default.
func (d *DB) Network(ctx context.Context) (NetworkSettings, error) {
	var n NetworkSettings
	err := d.GetSetting(ctx, SettingNetwork, &n)
	if errors.Is(err, ErrNotFound) {
		return DefaultNetwork, nil
	}
	return n, err
}

// bootstrapRecord is the stored form of the bootstrap token.
type bootstrapRecord struct {
	Hash []byte `json:"hash"`
}

// EnsureBootstrapToken returns a fresh bootstrap token if none exists yet
// (created=true), or "" if one is already stored.
func (d *DB) EnsureBootstrapToken(ctx context.Context) (token string, created bool, err error) {
	var rec bootstrapRecord
	err = d.GetSetting(ctx, SettingBootstrapToken, &rec)
	if err == nil {
		return "", false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", false, err
	}
	token, hash := NewToken("bgboot")
	if _, err := d.PutSetting(ctx, SettingBootstrapToken, bootstrapRecord{Hash: hash}, "system", false); err != nil {
		return "", false, err
	}
	return token, true, nil
}

// RotateBootstrapToken replaces the bootstrap token and returns the new one.
func (d *DB) RotateBootstrapToken(ctx context.Context) (string, error) {
	token, hash := NewToken("bgboot")
	_, err := d.PutSetting(ctx, SettingBootstrapToken, bootstrapRecord{Hash: hash}, "system", false)
	return token, err
}

// CheckBootstrapToken verifies a presented token.
func (d *DB) CheckBootstrapToken(ctx context.Context, token string) (bool, error) {
	var rec bootstrapRecord
	if err := d.GetSetting(ctx, SettingBootstrapToken, &rec); err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return hashEqual(rec.Hash, HashToken(token)), nil
}
