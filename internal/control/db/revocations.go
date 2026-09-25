package db

import (
	"context"
	"database/sql"
	"fmt"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// StoreRevocation spends the sign token and stores the admin-signed
// revocation of a revoked node; the snapshot version moves so every node
// receives it. The caller verified the signature.
func (d *DB) StoreRevocation(ctx context.Context, nodeID, token, revocation, signature, signedBy string) (uint64, error) {
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE sign_tokens SET used_at = ? WHERE token_hash = ? AND node_id = ? AND used_at IS NULL`, now(), HashToken(token), nodeID)
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return fmt.Errorf("%w: sign token", ErrTokenUsed)
		}
		var spki []byte
		if err := tx.QueryRowContext(ctx, `SELECT spki_hash FROM nodes WHERE id = ? AND status = 'revoked'`, nodeID).Scan(&spki); err != nil {
			return fmt.Errorf("%w: node is not revoked", ErrConflict)
		}
		_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO revocations (node_id, spki_hash, revocation, signature, signed_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			nodeID, spki, revocation, signature, signedBy, now())
		return err
	})
}

// Revocations are all signed revocations, as every snapshot carries them.
func (d *DB) Revocations(ctx context.Context) ([]registry.SignedRevocation, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT revocation, signature FROM revocations ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []registry.SignedRevocation
	for rows.Next() {
		var r registry.SignedRevocation
		if err := rows.Scan(&r.Revocation, &r.Signature); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevokedAndSigned lists the nodes whose revocation an admin signed.
func (d *DB) RevokedAndSigned(ctx context.Context) (map[string]bool, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT node_id FROM revocations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
