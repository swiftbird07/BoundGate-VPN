package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// LoginFlow is one OIDC authorization for a node. It is pending until the
// browser comes back from the identity provider, then confirm (the
// identity is known, the person has not yet confirmed the device), then
// done or failed.
type LoginFlow struct {
	ID               string
	NodeID           string
	State            string
	Nonce            string
	PKCEVerifier     string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	Status           string // pending | confirm | done | failed
	SessionID        string
	Error            string
	StartIP          string // where the node started the flow
	CallbackIP       string // where the browser came back from the IdP
	Identity         LoginIdentity
	ConfirmExpiresAt time.Time
}

// LoginIdentity is what the identity provider said about the person, kept
// on the flow between the callback and the confirmation.
type LoginIdentity struct {
	Subject  string   `json:"subject"`
	Email    string   `json:"email,omitempty"`
	Username string   `json:"username,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// LoginFlowTTL is how long a started login may take.
const LoginFlowTTL = 10 * time.Minute

// LoginConfirmTTL is how long the confirmation page stays valid.
const LoginConfirmTTL = 5 * time.Minute

// CreateLoginFlow starts a flow for a node. A node has at most maxOpen
// flows open (pending or awaiting confirmation): a new one fails the oldest
// beyond that.
func (d *DB) CreateLoginFlow(ctx context.Context, nodeID, state, nonce, verifier, startIP string, maxOpen int) (LoginFlow, error) {
	f := LoginFlow{ID: NewID(), NodeID: nodeID, State: state, Nonce: nonce, PKCEVerifier: verifier, StartIP: startIP,
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(LoginFlowTTL), Status: "pending"}
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		if maxOpen > 0 {
			rows, err := tx.QueryContext(ctx, `SELECT id FROM login_flows WHERE node_id = ? AND status IN ('pending', 'confirm') AND expires_at > ? ORDER BY created_at DESC`, nodeID, now())
			if err != nil {
				return err
			}
			var open []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				open = append(open, id)
			}
			if err := rows.Close(); err != nil {
				return err
			}
			for i := maxOpen - 1; i < len(open); i++ {
				if _, err := tx.ExecContext(ctx, `UPDATE login_flows SET status = 'failed', error = 'replaced by a newer login of this device', confirm_hash = NULL WHERE id = ?`, open[i]); err != nil {
					return err
				}
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO login_flows (id, node_id, state, nonce, pkce_verifier, created_at, expires_at, status, start_ip) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
			f.ID, f.NodeID, f.State, f.Nonce, f.PKCEVerifier, f.CreatedAt.Format(timeFormat), f.ExpiresAt.Format(timeFormat), f.StartIP)
		return err
	})
	return f, err
}

const flowCols = `id, node_id, state, nonce, pkce_verifier, created_at, expires_at, status, session_id, error, start_ip, callback_ip, identity_json, confirm_expires_at`

func scanFlow(sc scanner) (LoginFlow, error) {
	var f LoginFlow
	var created, expires, identity, confirmExpires string
	var session sql.NullString
	if err := sc.Scan(&f.ID, &f.NodeID, &f.State, &f.Nonce, &f.PKCEVerifier, &created, &expires, &f.Status, &session, &f.Error,
		&f.StartIP, &f.CallbackIP, &identity, &confirmExpires); err != nil {
		return f, err
	}
	f.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	f.ExpiresAt = parseTime(sql.NullString{String: expires, Valid: true})
	f.ConfirmExpiresAt = parseTime(sql.NullString{String: confirmExpires, Valid: true})
	f.SessionID = session.String
	if identity != "" {
		_ = json.Unmarshal([]byte(identity), &f.Identity)
	}
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

// AwaitLoginConfirmation stores the verified identity on a pending flow and
// returns the single-use token the confirmation page carries; only its hash
// is kept. The node keeps seeing the flow as pending until
// CompleteLoginFlow or FailLoginFlow.
func (d *DB) AwaitLoginConfirmation(ctx context.Context, id string, ident LoginIdentity, callbackIP string) (string, time.Time, error) {
	f, err := d.LoginFlowByID(ctx, id)
	if err != nil {
		return "", time.Time{}, err
	}
	token, hash := NewToken("bgconfirm")
	expires := time.Now().UTC().Add(LoginConfirmTTL)
	if f.ExpiresAt.Before(expires) {
		expires = f.ExpiresAt
	}
	raw, _ := json.Marshal(ident)
	res, err := d.sql.ExecContext(ctx, `UPDATE login_flows SET status = 'confirm', identity_json = ?, callback_ip = ?, confirm_hash = ?, confirm_expires_at = ? WHERE id = ? AND status = 'pending'`,
		string(raw), callbackIP, hash, expires.Format(timeFormat), id)
	if err != nil {
		return "", time.Time{}, err
	}
	if affected(res) != nil {
		return "", time.Time{}, ErrConflict
	}
	return token, expires, nil
}

// LoginFlowForConfirmation returns the flow a confirmation page belongs to:
// ErrNotFound for an unknown flow or a token that does not match,
// ErrConflict when the flow no longer awaits confirmation (done, cancelled,
// replaced), ErrTokenExpired when the page or the flow timed out.
func (d *DB) LoginFlowForConfirmation(ctx context.Context, id, token string) (LoginFlow, error) {
	f, err := d.LoginFlowByID(ctx, id)
	if err != nil {
		return f, err
	}
	var hash []byte
	if err := d.sql.QueryRowContext(ctx, `SELECT confirm_hash FROM login_flows WHERE id = ?`, id).Scan(&hash); err != nil {
		return f, err
	}
	if f.Status != "confirm" {
		return f, ErrConflict
	}
	if len(hash) == 0 || !hashEqual(hash, HashToken(token)) {
		return f, ErrNotFound
	}
	if !time.Now().Before(f.ConfirmExpiresAt) || !time.Now().Before(f.ExpiresAt) {
		return f, ErrTokenExpired
	}
	return f, nil
}

// FailLoginFlow records why a flow failed.
func (d *DB) FailLoginFlow(ctx context.Context, id, reason string) {
	_, _ = d.sql.ExecContext(ctx, `UPDATE login_flows SET status = 'failed', error = ?, confirm_hash = NULL WHERE id = ? AND status IN ('pending', 'confirm')`, reason, id)
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

// CompleteLoginFlow turns a confirmed flow into a session: any previous
// active session of the node ends ("replaced"), the new one is stored, the
// flow is marked done and the snapshot bumped. Only a flow awaiting
// confirmation (AwaitLoginConfirmation) can complete.
func (d *DB) CompleteLoginFlow(ctx context.Context, flowID string, s Session) (Session, uint64, error) {
	s.ID = NewID()
	if s.IssuedAt.IsZero() {
		s.IssuedAt = time.Now().UTC()
	}
	version, err := d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE login_flows SET status = 'done', session_id = ?, confirm_hash = NULL WHERE id = ? AND status = 'confirm'`, s.ID, flowID)
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
