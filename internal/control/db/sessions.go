package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// LoginFlow is one pending OIDC authorization for a node.
type LoginFlow struct {
	ID           string
	NodeID       string
	State        string
	Nonce        string
	PKCEVerifier string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Status       string // pending | done | failed
	SessionID    string
	Error        string
}

// LoginFlowTTL is how long a started login may take.
const LoginFlowTTL = 10 * time.Minute

// CreateLoginFlow starts a flow for a node.
func (d *DB) CreateLoginFlow(ctx context.Context, nodeID, state, nonce, verifier string) (LoginFlow, error) {
	f := LoginFlow{ID: NewID(), NodeID: nodeID, State: state, Nonce: nonce, PKCEVerifier: verifier,
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(LoginFlowTTL), Status: "pending"}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO login_flows (id, node_id, state, nonce, pkce_verifier, created_at, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
		f.ID, f.NodeID, f.State, f.Nonce, f.PKCEVerifier, f.CreatedAt.Format(timeFormat), f.ExpiresAt.Format(timeFormat))
	return f, err
}

const flowCols = `id, node_id, state, nonce, pkce_verifier, created_at, expires_at, status, session_id, error`

func scanFlow(sc scanner) (LoginFlow, error) {
	var f LoginFlow
	var created, expires string
	var session sql.NullString
	if err := sc.Scan(&f.ID, &f.NodeID, &f.State, &f.Nonce, &f.PKCEVerifier, &created, &expires, &f.Status, &session, &f.Error); err != nil {
		return f, err
	}
	f.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	f.ExpiresAt = parseTime(sql.NullString{String: expires, Valid: true})
	f.SessionID = session.String
	return f, nil
}

// LoginFlowByID returns a flow; ErrNotFound if unknown.
func (d *DB) LoginFlowByID(ctx context.Context, id string) (LoginFlow, error) {
	f, err := scanFlow(d.sql.QueryRowContext(ctx, `SELECT `+flowCols+` FROM login_flows WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return LoginFlow{}, ErrNotFound
	}
	return f, err
}

// LoginFlowByState returns a pending, unexpired flow by its OAuth state.
func (d *DB) LoginFlowByState(ctx context.Context, state string) (LoginFlow, error) {
	f, err := scanFlow(d.sql.QueryRowContext(ctx, `SELECT `+flowCols+` FROM login_flows WHERE state = ?`, state))
	if errors.Is(err, sql.ErrNoRows) {
		return LoginFlow{}, ErrNotFound
	}
	if err != nil {
		return f, err
	}
	if f.Status != "pending" {
		return f, ErrConflict
	}
	if !time.Now().Before(f.ExpiresAt) {
		return f, ErrTokenExpired
	}
	return f, nil
}

// FailLoginFlow records why a flow failed.
func (d *DB) FailLoginFlow(ctx context.Context, id, reason string) {
	_, _ = d.sql.ExecContext(ctx, `UPDATE login_flows SET status = 'failed', error = ? WHERE id = ? AND status = 'pending'`, reason, id)
}

// Session is an active user session bound to a node.
type Session struct {
	ID        string
	NodeID    string
	Subject   string
	Email     string
	Username  string
	Groups    []string
	LoginIP   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
	RevokedBy string
	EndReason string
}

const sessionCols = `id, node_id, subject, email, username, groups_json, login_ip, issued_at, expires_at, revoked_at, revoked_by, end_reason`

func scanSession(sc scanner) (Session, error) {
	var s Session
	var groups, issued, expires string
	var revokedAt, revokedBy sql.NullString
	if err := sc.Scan(&s.ID, &s.NodeID, &s.Subject, &s.Email, &s.Username, &groups, &s.LoginIP, &issued, &expires, &revokedAt, &revokedBy, &s.EndReason); err != nil {
		return s, err
	}
	_ = json.Unmarshal([]byte(groups), &s.Groups)
	s.IssuedAt = parseTime(sql.NullString{String: issued, Valid: true})
	s.ExpiresAt = parseTime(sql.NullString{String: expires, Valid: true})
	s.RevokedAt, s.RevokedBy = parseTime(revokedAt), revokedBy.String
	return s, nil
}

// CompleteLoginFlow turns a pending flow into a session: any previous
// active session of the node ends ("replaced"), the new one is stored, the
// flow is marked done and the snapshot bumped.
func (d *DB) CompleteLoginFlow(ctx context.Context, flowID string, s Session) (Session, uint64, error) {
	s.ID = NewID()
	if s.IssuedAt.IsZero() {
		s.IssuedAt = time.Now().UTC()
	}
	version, err := d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE login_flows SET status = 'done', session_id = ? WHERE id = ? AND status = 'pending'`, s.ID, flowID)
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = ?, revoked_by = 'node', end_reason = 'replaced' WHERE node_id = ? AND revoked_at IS NULL`, now(), s.NodeID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO user_sessions (`+sessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '')`,
			s.ID, s.NodeID, s.Subject, s.Email, s.Username, jsonOf(s.Groups), s.LoginIP, s.IssuedAt.Format(timeFormat), s.ExpiresAt.UTC().Format(timeFormat))
		return err
	})
	return s, version, err
}

// ActiveSessions returns unrevoked, unexpired sessions (for snapshots).
func (d *DB) ActiveSessions(ctx context.Context) ([]Session, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+sessionCols+` FROM user_sessions WHERE revoked_at IS NULL AND expires_at > ? ORDER BY issued_at`, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListSessions returns sessions, newest first; all includes ended ones.
func (d *DB) ListSessions(ctx context.Context, all bool) ([]Session, error) {
	q := `SELECT ` + sessionCols + ` FROM user_sessions`
	if !all {
		q += ` WHERE revoked_at IS NULL AND expires_at > '` + now() + `'`
	}
	rows, err := d.sql.QueryContext(ctx, q+` ORDER BY issued_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SessionByID fetches one session.
func (d *DB) SessionByID(ctx context.Context, id string) (Session, error) {
	s, err := scanSession(d.sql.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM user_sessions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return s, err
}

// SessionForNode returns the node's active session.
func (d *DB) SessionForNode(ctx context.Context, nodeID string) (Session, error) {
	s, err := scanSession(d.sql.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM user_sessions WHERE node_id = ? AND revoked_at IS NULL AND expires_at > ?`, nodeID, now()))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return s, err
}

// EndSession ends an active session (admin revoke or user logout) and bumps
// the snapshot.
func (d *DB) EndSession(ctx context.Context, id, by, reason string) (uint64, error) {
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = ?, revoked_by = ?, end_reason = ? WHERE id = ? AND revoked_at IS NULL`, now(), by, reason, id)
		if err != nil {
			return err
		}
		return affected(res)
	})
}

// ExpireSessions marks expired sessions ended and bumps the snapshot when
// any were; expired or finished login flows are deleted.
func (d *DB) ExpireSessions(ctx context.Context) (int64, uint64, error) {
	var n int64
	version, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = ?, revoked_by = 'system', end_reason = 'expired' WHERE revoked_at IS NULL AND expires_at <= ?`, now(), now())
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		if n > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE snapshot_version SET version = version + 1, updated_at = ?`, now()); err != nil {
				return err
			}
		}
		cutoff := time.Now().UTC().Add(-time.Hour).Format(timeFormat)
		_, err = tx.ExecContext(ctx, `DELETE FROM login_flows WHERE expires_at < ? OR (status <> 'pending' AND created_at < ?)`, cutoff, cutoff)
		return err
	})
	if n == 0 {
		version = 0
	}
	return n, version, err
}

// sessionEnded is a helper for tests.
func (s Session) Active(at time.Time) bool { return s.RevokedAt.IsZero() && at.Before(s.ExpiresAt) }

var _ = strings.TrimSpace
