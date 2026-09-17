package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// Signer is an admin signing key.
type Signer struct {
	ID          string
	Subject     string
	Name        string
	PublicKey   string // "type base64"
	KeyType     string
	Hardware    bool
	Fingerprint string
	CreatedAt   time.Time
	RevokedAt   time.Time
}

// AuthorizedKey returns the key as an authorized_keys line with the name as
// comment.
func (s Signer) AuthorizedKey() string {
	return s.PublicKey + " " + strings.ReplaceAll(s.Name, " ", "_")
}

const signerCols = `id, subject, name, ssh_pubkey, key_type, hardware, fingerprint, created_at, revoked_at`

func scanSigner(sc scanner) (Signer, error) {
	var s Signer
	var created string
	var revoked sql.NullString
	if err := sc.Scan(&s.ID, &s.Subject, &s.Name, &s.PublicKey, &s.KeyType, &s.Hardware, &s.Fingerprint, &created, &revoked); err != nil {
		return s, err
	}
	s.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	s.RevokedAt = parseTime(revoked)
	return s, nil
}

// AddSigner registers a key. The same key twice is a conflict.
func (d *DB) AddSigner(ctx context.Context, s Signer) (Signer, error) {
	s.ID = NewID()
	if strings.TrimSpace(s.Name) == "" {
		s.Name = "admin-key-" + s.ID[:6]
	}
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO admin_signers (`+signerCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			s.ID, s.Subject, s.Name, s.PublicKey, s.KeyType, s.Hardware, s.Fingerprint, now())
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return err
	})
	if err != nil {
		return Signer{}, err
	}
	return d.SignerByID(ctx, s.ID)
}

// SignerByID fetches one signer.
func (d *DB) SignerByID(ctx context.Context, id string) (Signer, error) {
	s, err := scanSigner(d.sql.QueryRowContext(ctx, `SELECT `+signerCols+` FROM admin_signers WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Signer{}, ErrNotFound
	}
	return s, err
}

// ListSigners returns all signers (activeOnly drops revoked ones), oldest first.
func (d *DB) ListSigners(ctx context.Context, activeOnly bool) ([]Signer, error) {
	q := `SELECT ` + signerCols + ` FROM admin_signers`
	if activeOnly {
		q += ` WHERE revoked_at IS NULL`
	}
	rows, err := d.sql.QueryContext(ctx, q+` ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Signer
	for rows.Next() {
		s, err := scanSigner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RevokeSigner marks a key revoked; it no longer verifies new signatures at
// the control plane. Nodes keep whatever they pinned.
func (d *DB) RevokeSigner(ctx context.Context, id string) error {
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE admin_signers SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now(), id)
		if err != nil {
			return err
		}
		return affected(res)
	})
	return err
}

// SignToken is a one-time authorization for the CLI signing step.
type SignToken struct {
	NodeID    string
	SPKI      devicekey.SPKIHash
	Admin     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

// SignTokenTTL is how long a sign token is valid.
const SignTokenTTL = 10 * time.Minute

// CreateSignToken mints a token for a confirmed node and returns the secret
// (shown once). Older unused tokens of the node are invalidated.
func (d *DB) CreateSignToken(ctx context.Context, nodeID string, spki devicekey.SPKIHash, admin string) (string, time.Time, error) {
	token, hash := NewToken("bgsign")
	expires := time.Now().UTC().Add(SignTokenTTL)
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sign_tokens WHERE node_id = ? AND used_at IS NULL`, nodeID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO sign_tokens (token_hash, node_id, spki_hash, admin, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			hash, nodeID, spki[:], admin, now(), expires.Format(timeFormat))
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// Errors for sign tokens.
var (
	ErrTokenUsed    = errors.New("db: sign token already used")
	ErrTokenExpired = errors.New("db: sign token expired")
)

// LookupSignToken validates a presented token: known, unused, unexpired.
func (d *DB) LookupSignToken(ctx context.Context, token string) (SignToken, error) {
	if !strings.HasPrefix(strings.TrimSpace(token), "bgsign_") {
		return SignToken{}, ErrNotFound
	}
	var t SignToken
	var spki []byte
	var created, expires string
	var used sql.NullString
	err := d.sql.QueryRowContext(ctx, `SELECT node_id, spki_hash, admin, created_at, expires_at, used_at FROM sign_tokens WHERE token_hash = ?`, HashToken(token)).
		Scan(&t.NodeID, &spki, &t.Admin, &created, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return SignToken{}, ErrNotFound
	}
	if err != nil {
		return SignToken{}, err
	}
	copy(t.SPKI[:], spki)
	t.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	t.ExpiresAt = parseTime(sql.NullString{String: expires, Valid: true})
	t.UsedAt = parseTime(used)
	if !t.UsedAt.IsZero() {
		return t, ErrTokenUsed
	}
	if !time.Now().Before(t.ExpiresAt) {
		return t, ErrTokenExpired
	}
	return t, nil
}

// ExpireSignTokens deletes tokens that are expired or used for longer than a day.
func (d *DB) ExpireSignTokens(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(timeFormat)
	res, err := d.sql.ExecContext(ctx, `DELETE FROM sign_tokens WHERE expires_at < ? OR used_at < ?`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
