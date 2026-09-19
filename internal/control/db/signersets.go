package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// SignerSetRow is one stored link of the signed admin key list. The
// database only stores what package binding verified; nothing here decides
// whether a set is valid.
type SignerSetRow struct {
	Version   uint64
	Set       string
	Signature string
	Hash      string
	SignedBy  string
	Admin     string
	CreatedAt time.Time
}

// SignerChain returns all links, oldest first.
func (d *DB) SignerChain(ctx context.Context) ([]SignerSetRow, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT version, set_json, signature, hash, signed_by, admin, created_at FROM signer_sets ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignerSetRow
	for rows.Next() {
		var r SignerSetRow
		var created string
		if err := rows.Scan(&r.Version, &r.Set, &r.Signature, &r.Hash, &r.SignedBy, &r.Admin, &created); err != nil {
			return nil, err
		}
		r.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
		out = append(out, r)
	}
	return out, rows.Err()
}

// SignerLinks is the chain in the form nodes receive.
func (d *DB) SignerLinks(ctx context.Context) ([]registry.SignerLink, error) {
	rows, err := d.SignerChain(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]registry.SignerLink, 0, len(rows))
	for _, r := range rows {
		out = append(out, registry.SignerLink{Set: r.Set, Signature: r.Signature})
	}
	return out, nil
}

// SignerKeyMeta is what the directory (admin_signers) records about a key
// of a set. PublicKey is "type base64".
type SignerKeyMeta struct {
	PublicKey   string `json:"public_key"`
	Name        string `json:"name"`
	Subject     string `json:"subject"`
	KeyType     string `json:"key_type"`
	Hardware    bool   `json:"hardware"`
	Fingerprint string `json:"fingerprint"`
}

// SignerChange is a proposed next set waiting for its signature.
type SignerChange struct {
	Set       string
	Keys      []SignerKeyMeta
	Admin     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSignerChange stores a proposal and returns its one-time token.
// There is one open proposal at a time: older unused ones are dropped.
func (d *DB) CreateSignerChange(ctx context.Context, set string, keys []SignerKeyMeta, admin string) (string, time.Time, error) {
	meta, err := json.Marshal(keys)
	if err != nil {
		return "", time.Time{}, err
	}
	token, hash := NewToken("bgsigners")
	expires := time.Now().UTC().Add(SignTokenTTL)
	_, err = d.tx(ctx, false, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM signer_changes WHERE used_at IS NULL`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO signer_changes (token_hash, set_json, meta_json, admin, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			hash, set, string(meta), admin, now(), expires.Format(timeFormat))
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// LookupSignerChange finds the proposal behind a token.
func (d *DB) LookupSignerChange(ctx context.Context, token string) (SignerChange, error) {
	if !strings.HasPrefix(strings.TrimSpace(token), "bgsigners_") {
		return SignerChange{}, ErrNotFound
	}
	var c SignerChange
	var meta, created, expires string
	var used sql.NullString
	err := d.sql.QueryRowContext(ctx, `SELECT set_json, meta_json, admin, created_at, expires_at, used_at FROM signer_changes WHERE token_hash = ?`, HashToken(token)).
		Scan(&c.Set, &meta, &c.Admin, &created, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return SignerChange{}, ErrNotFound
	}
	if err != nil {
		return SignerChange{}, err
	}
	if err := json.Unmarshal([]byte(meta), &c.Keys); err != nil {
		return SignerChange{}, err
	}
	c.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	c.ExpiresAt = parseTime(sql.NullString{String: expires, Valid: true})
	if used.Valid && used.String != "" {
		return c, ErrTokenUsed
	}
	if !time.Now().Before(c.ExpiresAt) {
		return c, ErrTokenExpired
	}
	return c, nil
}

// ApplySignerSet stores a verified set as the new head, all or nothing:
// the token is spent, the link is appended (the version must be exactly the
// next one, so two admins cannot both extend the same head), the directory
// follows the set, and every approved node whose binding was signed by a key
// that is no longer in the list goes back to "confirmed": its peers refuse
// that signature from now on, so it needs a new one. Returns the snapshot
// version and the ids of the demoted nodes.
func (d *DB) ApplySignerSet(ctx context.Context, token string, row SignerSetRow, keys []SignerKeyMeta) (uint64, []string, error) {
	var demoted []string
	version, err := d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE signer_changes SET used_at = ? WHERE token_hash = ? AND used_at IS NULL`, now(), HashToken(token))
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return fmt.Errorf("%w: signer change token", ErrTokenUsed)
		}
		var head uint64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM signer_sets`).Scan(&head); err != nil {
			return err
		}
		if row.Version != head+1 {
			return fmt.Errorf("%w: the admin key list is at version %d now; propose the change again", ErrConflict, head)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO signer_sets (version, set_json, signature, hash, signed_by, admin, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			row.Version, row.Set, row.Signature, row.Hash, row.SignedBy, row.Admin, now()); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") {
				return fmt.Errorf("%w: signer set %d exists", ErrConflict, row.Version)
			}
			return err
		}
		// the directory follows the set
		if _, err := tx.ExecContext(ctx, `UPDATE admin_signers SET revoked_at = COALESCE(revoked_at, ?)`, now()); err != nil {
			return err
		}
		var fps []any
		for _, k := range keys {
			res, err := tx.ExecContext(ctx, `UPDATE admin_signers SET revoked_at = NULL WHERE ssh_pubkey = ?`, k.PublicKey)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				name := strings.TrimSpace(k.Name)
				id := NewID()
				if name == "" {
					name = "admin-key-" + id[:6]
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO admin_signers (`+signerCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
					id, k.Subject, name, k.PublicKey, k.KeyType, k.Hardware, k.Fingerprint, now()); err != nil {
					return err
				}
			}
			fps = append(fps, k.Fingerprint)
		}
		// nodes whose signature no longer counts
		q := `SELECT id FROM nodes WHERE status = 'approved' AND signed_by NOT IN (?` + strings.Repeat(",?", len(fps)-1) + `)`
		rows, err := tx.QueryContext(ctx, q, fps...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			demoted = append(demoted, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range demoted {
			if _, err := tx.ExecContext(ctx, `UPDATE nodes SET status = 'confirmed', binding_json = '', binding_sig = '', signed_by = '', signed_at = NULL, approved_at = NULL, approved_by = NULL WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return version, demoted, nil
}

// NodesSignedBy lists approved nodes whose binding carries one of the
// given signer fingerprints (what a removal would demote).
func (d *DB) NodesSignedBy(ctx context.Context, fingerprints []string) ([]Node, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	all, err := d.ListNodes(ctx, StatusApproved)
	if err != nil {
		return nil, err
	}
	var out []Node
	for _, n := range all {
		for _, fp := range fingerprints {
			if n.SignedBy == fp {
				out = append(out, n)
				break
			}
		}
	}
	return out, nil
}

// ExpireSignerChanges deletes proposals that are expired or used for longer than a day.
func (d *DB) ExpireSignerChanges(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(timeFormat)
	res, err := d.sql.ExecContext(ctx, `DELETE FROM signer_changes WHERE expires_at < ? OR used_at < ?`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
