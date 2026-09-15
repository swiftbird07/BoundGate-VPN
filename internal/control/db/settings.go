package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
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

// Validate checks the settings.
func (n NetworkSettings) Validate() error {
	if !n.Pool.IsValid() || !n.Pool.Addr().Is4() || n.Pool.Bits() > 30 {
		return errors.New("pool must be an IPv4 prefix of /30 or larger")
	}
	if n.Pool.Masked() != n.Pool {
		return errors.New("pool must be a network address (host bits zero)")
	}
	if n.MaxAgeSeconds < 0 {
		return errors.New("max_age_seconds must not be negative")
	}
	return nil
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
