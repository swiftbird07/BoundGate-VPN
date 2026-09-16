package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Policy is a row of policies: one Cedar document (one or more statements)
// with the nodes it is distributed to.
type Policy struct {
	ID          string
	Name        string
	Description string
	Cedar       string
	Enabled     bool
	// Scope lists node ids that receive the policy; empty means all.
	Scope     []string
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// AppliesTo reports whether a node receives the policy.
func (p Policy) AppliesTo(nodeID string) bool {
	if len(p.Scope) == 0 {
		return true
	}
	for _, id := range p.Scope {
		if id == nodeID {
			return true
		}
	}
	return false
}

const policyCols = `id, name, description, cedar, enabled, scope_json, created_at, created_by, updated_at, updated_by`

func scanPolicy(s scanner) (Policy, error) {
	var p Policy
	var scope, created, updated string
	if err := s.Scan(&p.ID, &p.Name, &p.Description, &p.Cedar, &p.Enabled, &scope, &created, &p.CreatedBy, &updated, &p.UpdatedBy); err != nil {
		return Policy{}, err
	}
	_ = json.Unmarshal([]byte(scope), &p.Scope)
	if p.Scope == nil {
		p.Scope = []string{}
	}
	p.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	p.UpdatedAt = parseTime(sql.NullString{String: updated, Valid: true})
	return p, nil
}

// ListPolicies returns every policy, by name.
func (d *DB) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+policyCols+` FROM policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// EnabledPolicies returns the policies nodes receive.
func (d *DB) EnabledPolicies(ctx context.Context) ([]Policy, error) {
	all, err := d.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, p := range all {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out, nil
}

// PolicyByID loads one policy.
func (d *DB) PolicyByID(ctx context.Context, id string) (Policy, error) {
	p, err := scanPolicy(d.sql.QueryRowContext(ctx, `SELECT `+policyCols+` FROM policies WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	return p, err
}

// CreatePolicy stores a validated policy and bumps the snapshot.
func (d *DB) CreatePolicy(ctx context.Context, p Policy, by string) (Policy, uint64, error) {
	p.ID = NewID()
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return Policy{}, 0, errors.New("db: policy name required")
	}
	if p.Scope == nil {
		p.Scope = []string{}
	}
	scope, _ := json.Marshal(p.Scope)
	ts := now()
	p.CreatedBy, p.UpdatedBy = by, by
	version, err := d.tx(ctx, true, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO policies (`+policyCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.ID, p.Name, p.Description, p.Cedar, p.Enabled, string(scope), ts, by, ts, by)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return err
	})
	if err != nil {
		return Policy{}, 0, err
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	p.UpdatedAt = p.CreatedAt
	return p, version, nil
}

// UpdatePolicy replaces name, description, cedar, enabled and scope.
func (d *DB) UpdatePolicy(ctx context.Context, p Policy, by string) (uint64, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return 0, errors.New("db: policy name required")
	}
	if p.Scope == nil {
		p.Scope = []string{}
	}
	scope, _ := json.Marshal(p.Scope)
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE policies SET name = ?, description = ?, cedar = ?, enabled = ?, scope_json = ?, updated_at = ?, updated_by = ? WHERE id = ?`,
			p.Name, p.Description, p.Cedar, p.Enabled, string(scope), now(), by, p.ID)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrConflict
			}
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// DeletePolicy removes a policy.
func (d *DB) DeletePolicy(ctx context.Context, id string) (uint64, error) {
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}
