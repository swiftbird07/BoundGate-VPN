package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Admin authentication (M4): OIDC login flows for admins, browser sessions
// with a level (oidc_only until a passkey assertion), passkeys and API
// tokens. The bootstrap token is only honoured while no active passkey
// exists (see CountActivePasskeys).

// AdminLevel of a session.
type AdminLevel string

const (
	AdminLevelOIDC AdminLevel = "oidc_only"
	AdminLevelFull AdminLevel = "full"
)

// AdminLoginFlow is a pending OIDC authorization for a browser.
type AdminLoginFlow struct {
	ID           string
	State        string
	Nonce        string
	PKCEVerifier string
	Next         string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Status       string
	Error        string
}

// CreateAdminLoginFlow starts an admin login.
func (d *DB) CreateAdminLoginFlow(ctx context.Context, state, nonce, verifier, next string) (AdminLoginFlow, error) {
	f := AdminLoginFlow{ID: NewID(), State: state, Nonce: nonce, PKCEVerifier: verifier, Next: next,
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(LoginFlowTTL), Status: "pending"}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_login_flows (id, state, nonce, pkce_verifier, next, created_at, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
		f.ID, f.State, f.Nonce, f.PKCEVerifier, f.Next, f.CreatedAt.Format(timeFormat), f.ExpiresAt.Format(timeFormat))
	return f, err
}

// AdminLoginFlowByState returns a pending, unexpired admin flow.
func (d *DB) AdminLoginFlowByState(ctx context.Context, state string) (AdminLoginFlow, error) {
	var f AdminLoginFlow
	var created, expires string
	err := d.sql.QueryRowContext(ctx, `SELECT id, state, nonce, pkce_verifier, next, created_at, expires_at, status, error FROM admin_login_flows WHERE state = ?`, state).
		Scan(&f.ID, &f.State, &f.Nonce, &f.PKCEVerifier, &f.Next, &created, &expires, &f.Status, &f.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, err
	}
	f.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	f.ExpiresAt = parseTime(sql.NullString{String: expires, Valid: true})
	if f.Status != "pending" {
		return f, ErrConflict
	}
	if !time.Now().Before(f.ExpiresAt) {
		return f, ErrTokenExpired
	}
	return f, nil
}

// FinishAdminLoginFlow marks a flow done or failed.
func (d *DB) FinishAdminLoginFlow(ctx context.Context, id, status, reason string) {
	_, _ = d.sql.ExecContext(ctx, `UPDATE admin_login_flows SET status = ?, error = ? WHERE id = ? AND status = 'pending'`, status, reason, id)
}

// AdminSession is a browser session.
type AdminSession struct {
	ID         string
	Subject    string
	Email      string
	Name       string
	Groups     []string
	Level      AdminLevel
	LoginIP    string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	RevokedAt  time.Time
	Ceremony   string // WebAuthn session data between begin and finish
}

const adminSessionCols = `id, subject, email, name, groups_json, level, login_ip, created_at, expires_at, last_seen_at, revoked_at, ceremony_json`

func scanAdminSession(sc scanner) (AdminSession, error) {
	var s AdminSession
	var groups, created, expires, seen string
	var revoked sql.NullString
	if err := sc.Scan(&s.ID, &s.Subject, &s.Email, &s.Name, &groups, &s.Level, &s.LoginIP, &created, &expires, &seen, &revoked, &s.Ceremony); err != nil {
		return s, err
	}
	_ = json.Unmarshal([]byte(groups), &s.Groups)
	s.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	s.ExpiresAt = parseTime(sql.NullString{String: expires, Valid: true})
	s.LastSeenAt = parseTime(sql.NullString{String: seen, Valid: true})
	s.RevokedAt = parseTime(revoked)
	return s, nil
}

// CreateAdminSession stores a new session; the id is the cookie value.
func (d *DB) CreateAdminSession(ctx context.Context, s AdminSession, lifetime time.Duration) (AdminSession, error) {
	s.ID, _ = NewToken("bgadm")
	now := time.Now().UTC()
	s.CreatedAt, s.LastSeenAt, s.ExpiresAt = now, now, now.Add(lifetime)
	if s.Level == "" {
		s.Level = AdminLevelOIDC
	}
	if s.Groups == nil {
		s.Groups = []string{}
	}
	groups, _ := json.Marshal(s.Groups)
	_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_sessions (`+adminSessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '')`,
		s.ID, s.Subject, s.Email, s.Name, string(groups), s.Level, s.LoginIP, now.Format(timeFormat), s.ExpiresAt.Format(timeFormat), now.Format(timeFormat))
	return s, err
}

// AdminSessionByID returns a live session (unexpired, not revoked) and
// records that it was used.
func (d *DB) AdminSessionByID(ctx context.Context, id string) (AdminSession, error) {
	s, err := scanAdminSession(d.sql.QueryRowContext(ctx, `SELECT `+adminSessionCols+` FROM admin_sessions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, err
	}
	if !s.RevokedAt.IsZero() || !time.Now().Before(s.ExpiresAt) {
		return s, ErrTokenExpired
	}
	_, _ = d.sql.ExecContext(ctx, `UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?`, now(), id)
	return s, nil
}

// RaiseAdminSession replaces a live session by a new one at level, with a
// new id (the cookie value) and the same identity and expiry; the old id
// is revoked. An id a browser carried before the passkey assertion must
// not be the one that carries full rights afterwards (session fixation).
func (d *DB) RaiseAdminSession(ctx context.Context, id string, level AdminLevel) (AdminSession, error) {
	var s AdminSession
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		var err error
		s, err = scanAdminSession(tx.QueryRowContext(ctx, `SELECT `+adminSessionCols+` FROM admin_sessions WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !s.RevokedAt.IsZero() || !time.Now().Before(s.ExpiresAt) {
			return ErrTokenExpired
		}
		s.ID, _ = NewToken("bgadm")
		s.Level, s.Ceremony = level, ""
		if s.Groups == nil {
			s.Groups = []string{}
		}
		groups, _ := json.Marshal(s.Groups)
		if _, err := tx.ExecContext(ctx, `INSERT INTO admin_sessions (`+adminSessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '')`,
			s.ID, s.Subject, s.Email, s.Name, string(groups), s.Level, s.LoginIP, s.CreatedAt.UTC().Format(timeFormat), s.ExpiresAt.UTC().Format(timeFormat), now()); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at = ?, ceremony_json = '' WHERE id = ?`, now(), id)
		return err
	})
	return s, err
}

// SetAdminCeremony stores WebAuthn session data for the session ("" clears).
func (d *DB) SetAdminCeremony(ctx context.Context, id, ceremony string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE admin_sessions SET ceremony_json = ? WHERE id = ?`, ceremony, id)
	return err
}

// RevokeAdminSession ends a session.
func (d *DB) RevokeAdminSession(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now(), id)
	return err
}

// ListAdminSessions returns live sessions.
func (d *DB) ListAdminSessions(ctx context.Context) ([]AdminSession, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+adminSessionCols+` FROM admin_sessions WHERE revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC`, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminSession
	for rows.Next() {
		s, err := scanAdminSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ExpireAdminSessions deletes sessions that ended more than a day ago and
// login flows past their expiry (ten minutes, finished or not). The login
// entry point is unauthenticated, so the housekeeping loop runs this every
// minute.
func (d *DB) ExpireAdminSessions(ctx context.Context) error {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(timeFormat)
	if _, err := d.sql.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at < ? OR revoked_at < ?`, cutoff, cutoff); err != nil {
		return err
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM admin_login_flows WHERE expires_at < ?`, now())
	return err
}

// CountPendingAdminLoginFlows returns how many admin logins are waiting for
// the identity provider.
func (d *DB) CountPendingAdminLoginFlows(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_login_flows WHERE status = 'pending' AND expires_at > ?`, now()).Scan(&n)
	return n, err
}

// Passkey is a registered WebAuthn credential of an admin.
type Passkey struct {
	ID           string
	Subject      string
	Email        string
	Label        string
	Credential   []byte // webauthn.Credential as JSON
	CredentialID []byte
	Status       string // pending | active | revoked
	CreatedAt    time.Time
	ApprovedAt   time.Time
	ApprovedBy   string
	LastUsedAt   time.Time
	RevokedAt    time.Time
	RevokedBy    string
}

const passkeyCols = `id, subject, email, label, credential_json, credential_id, status, created_at, approved_at, approved_by, last_used_at, revoked_at, revoked_by`

func scanPasskey(sc scanner) (Passkey, error) {
	var p Passkey
	var cred, created string
	var approvedAt, approvedBy, used, revokedAt, revokedBy sql.NullString
	if err := sc.Scan(&p.ID, &p.Subject, &p.Email, &p.Label, &cred, &p.CredentialID, &p.Status, &created, &approvedAt, &approvedBy, &used, &revokedAt, &revokedBy); err != nil {
		return p, err
	}
	p.Credential = []byte(cred)
	p.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	p.ApprovedAt, p.ApprovedBy = parseTime(approvedAt), approvedBy.String
	p.LastUsedAt = parseTime(used)
	p.RevokedAt, p.RevokedBy = parseTime(revokedAt), revokedBy.String
	return p, nil
}

// AddPasskey stores a credential with the given status.
func (d *DB) AddPasskey(ctx context.Context, p Passkey, by string) (Passkey, error) {
	p.ID = NewID()
	p.CreatedAt = time.Now().UTC()
	var approvedAt, approvedBy any
	if p.Status == "active" {
		approvedAt, approvedBy = now(), by
		p.ApprovedBy = by
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_passkeys (id, subject, email, label, credential_json, credential_id, status, created_at, approved_at, approved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Subject, p.Email, p.Label, string(p.Credential), p.CredentialID, p.Status, p.CreatedAt.Format(timeFormat), approvedAt, approvedBy)
	if err != nil && isUnique(err) {
		return p, ErrConflict
	}
	return p, err
}

// PasskeyByID loads one passkey.
func (d *DB) PasskeyByID(ctx context.Context, id string) (Passkey, error) {
	p, err := scanPasskey(d.sql.QueryRowContext(ctx, `SELECT `+passkeyCols+` FROM admin_passkeys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// ListPasskeys returns every passkey (all admins), or only one subject's.
func (d *DB) ListPasskeys(ctx context.Context, subject string) ([]Passkey, error) {
	q := `SELECT ` + passkeyCols + ` FROM admin_passkeys`
	var args []any
	if subject != "" {
		q += ` WHERE subject = ?`
		args = append(args, subject)
	}
	q += ` ORDER BY created_at`
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountActivePasskeys says whether the bootstrap token is still valid
// (it is only while this is zero).
func (d *DB) CountActivePasskeys(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_passkeys WHERE status = 'active'`).Scan(&n)
	return n, err
}

// UpdatePasskeyCredential stores the credential after use (sign counter,
// flags) and the last-used time.
func (d *DB) UpdatePasskeyCredential(ctx context.Context, id string, cred []byte) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE admin_passkeys SET credential_json = ?, last_used_at = ? WHERE id = ?`, string(cred), now(), id)
	return err
}

// ApprovePasskey activates a pending passkey.
func (d *DB) ApprovePasskey(ctx context.Context, id, by string) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE admin_passkeys SET status = 'active', approved_at = ?, approved_by = ? WHERE id = ? AND status = 'pending'`, now(), by, id)
	if err != nil {
		return err
	}
	return affected(res)
}

// RevokePasskey disables a passkey (pending or active).
func (d *DB) RevokePasskey(ctx context.Context, id, by string) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE admin_passkeys SET status = 'revoked', revoked_at = ?, revoked_by = ? WHERE id = ? AND status <> 'revoked'`, now(), by, id)
	if err != nil {
		return err
	}
	return affected(res)
}

// APIToken is a long-lived bearer credential for automation.
type APIToken struct {
	ID         string
	Name       string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
	RevokedBy  string
	// Bootstrap: minted with the bootstrap token; it dies with it, when the
	// first passkey is active (R54).
	Bootstrap bool
}

const apiTokenCols = `id, name, created_by, created_at, expires_at, last_used_at, revoked_at, revoked_by, bootstrap`

func scanAPIToken(sc scanner) (APIToken, error) {
	var t APIToken
	var created string
	var expires, used, revokedAt, revokedBy sql.NullString
	if err := sc.Scan(&t.ID, &t.Name, &t.CreatedBy, &created, &expires, &used, &revokedAt, &revokedBy, &t.Bootstrap); err != nil {
		return t, err
	}
	t.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	t.ExpiresAt, t.LastUsedAt, t.RevokedAt, t.RevokedBy = parseTime(expires), parseTime(used), parseTime(revokedAt), revokedBy.String
	return t, nil
}

// CreateAPIToken mints a token; the secret is returned once. bootstrap
// says it was minted with the bootstrap token.
func (d *DB) CreateAPIToken(ctx context.Context, name, by string, expires time.Time, bootstrap bool) (APIToken, string, error) {
	secret, hash := NewToken("bgapi")
	t := APIToken{ID: NewID(), Name: name, CreatedBy: by, CreatedAt: time.Now().UTC(), ExpiresAt: expires, Bootstrap: bootstrap}
	var exp any
	if !expires.IsZero() {
		exp = expires.UTC().Format(timeFormat)
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO api_tokens (id, name, token_hash, created_by, created_at, expires_at, bootstrap) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, hash, by, t.CreatedAt.Format(timeFormat), exp, bootstrap)
	return t, secret, err
}

// LookupAPIToken resolves a presented bearer token. A token minted with
// the bootstrap token is dead while a passkey is active, like the
// bootstrap token itself (RevokeBootstrapAPITokens revokes it for good).
func (d *DB) LookupAPIToken(ctx context.Context, secret string) (APIToken, error) {
	t, err := scanAPIToken(d.sql.QueryRowContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE token_hash = ?`, HashToken(secret)))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	if !t.RevokedAt.IsZero() || (!t.ExpiresAt.IsZero() && !time.Now().Before(t.ExpiresAt)) {
		return t, ErrTokenExpired
	}
	if t.Bootstrap {
		if n, err := d.CountActivePasskeys(ctx); err != nil {
			return t, err
		} else if n > 0 {
			return t, ErrTokenExpired
		}
	}
	_, _ = d.sql.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now(), t.ID)
	return t, nil
}

// RevokeBootstrapAPITokens revokes every live token minted with the
// bootstrap token; the first passkey calls it.
func (d *DB) RevokeBootstrapAPITokens(ctx context.Context, by string) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ?, revoked_by = ? WHERE bootstrap = 1 AND revoked_at IS NULL`, now(), by)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokeAllPasskeys revokes every pending and active passkey: the way back
// in for the operator of the control-plane host after the only passkey was
// lost (boundgate-control rotate-bootstrap-token -revoke-passkeys).
func (d *DB) RevokeAllPasskeys(ctx context.Context, by string) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE admin_passkeys SET status = 'revoked', revoked_at = ?, revoked_by = ? WHERE status <> 'revoked'`, now(), by)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListAPITokens returns every token, revoked ones included.
func (d *DB) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken disables a token.
func (d *DB) RevokeAPIToken(ctx context.Context, id, by string) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`, now(), by, id)
	if err != nil {
		return err
	}
	return affected(res)
}

func isUnique(err error) bool {
	return err != nil && (contains(err.Error(), "UNIQUE") || contains(err.Error(), "unique"))
}

func contains(s, sub string) bool {
	return len(sub) <= len(s) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
