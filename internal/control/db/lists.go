package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// List is a row of lists: a named set policies refer to as
// BoundGate::List::"<name>".
type List struct {
	ID          string
	Name        string
	Kind        string // ip | dns | sni
	Description string
	Entries     []string
	CreatedAt   time.Time
	CreatedBy   string
	UpdatedAt   time.Time
	UpdatedBy   string
}

// ListKinds are the kinds a list can have.
var ListKinds = []string{"ip", "dns", "sni"}

// MaxListEntries bounds a list: every node carries every list in its snapshot.
const MaxListEntries = 10000

var listNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var listNameLabelRe = regexp.MustCompile(`^(\*|[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)$`)

// CleanListName lowercases and checks a list name.
func CleanListName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !listNameRe.MatchString(s) {
		return "", errors.New("list name: lowercase letters, digits, . _ - ; 1-64 characters")
	}
	return s, nil
}

// CleanListEntries normalizes entries for a kind: addresses and prefixes for
// ip (a plain address becomes a /32), lowercase names for dns and sni,
// where a leading "*." matches any number of labels. Empty lines and
// comments (#) are dropped, duplicates removed, the result sorted.
func CleanListEntries(kind string, in []string) ([]string, error) {
	if !slices.Contains(ListKinds, kind) {
		return nil, fmt.Errorf("list kind %q: one of ip, dns, sni", kind)
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		e := strings.TrimSpace(raw)
		if i := strings.IndexByte(e, '#'); i >= 0 {
			e = strings.TrimSpace(e[:i])
		}
		if e == "" {
			continue
		}
		if kind == "ip" {
			if p, err := netip.ParsePrefix(e); err == nil {
				out = append(out, p.Masked().String())
				continue
			}
			if a, err := netip.ParseAddr(e); err == nil {
				out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String())
				continue
			}
			return nil, fmt.Errorf("entry %q: an address or a CIDR prefix", e)
		}
		e = strings.ToLower(strings.TrimSuffix(e, "."))
		if len(e) > 253 {
			return nil, fmt.Errorf("entry %q: too long", e)
		}
		for i, l := range strings.Split(e, ".") {
			if !listNameLabelRe.MatchString(l) || (l == "*" && i != 0) {
				return nil, fmt.Errorf("entry %q: a host name, optionally starting with *.", e)
			}
		}
		out = append(out, e)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxListEntries {
		return nil, fmt.Errorf("more than %d entries", MaxListEntries)
	}
	return out, nil
}

const listCols = `id, name, kind, description, entries_json, created_at, created_by, updated_at, updated_by`

func scanList(s scanner) (List, error) {
	var l List
	var entries, created, updated string
	if err := s.Scan(&l.ID, &l.Name, &l.Kind, &l.Description, &entries, &created, &l.CreatedBy, &updated, &l.UpdatedBy); err != nil {
		return List{}, err
	}
	_ = json.Unmarshal([]byte(entries), &l.Entries)
	if l.Entries == nil {
		l.Entries = []string{}
	}
	l.CreatedAt = parseTime(sql.NullString{String: created, Valid: true})
	l.UpdatedAt = parseTime(sql.NullString{String: updated, Valid: true})
	return l, nil
}

// Lists returns every list, by name.
func (d *DB) Lists(ctx context.Context) ([]List, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+listCols+` FROM lists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []List
	for rows.Next() {
		l, err := scanList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListByID loads one list.
func (d *DB) ListByID(ctx context.Context, id string) (List, error) {
	l, err := scanList(d.sql.QueryRowContext(ctx, `SELECT `+listCols+` FROM lists WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return List{}, ErrNotFound
	}
	return l, err
}

// CreateList stores a cleaned list and bumps the snapshot.
func (d *DB) CreateList(ctx context.Context, l List, by string) (List, uint64, error) {
	l.ID = NewID()
	entries, _ := json.Marshal(l.Entries)
	ts := now()
	l.CreatedBy, l.UpdatedBy = by, by
	version, err := d.tx(ctx, true, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO lists (`+listCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			l.ID, l.Name, l.Kind, l.Description, string(entries), ts, by, ts, by)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return err
	})
	if err != nil {
		return List{}, 0, err
	}
	l.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	l.UpdatedAt = l.CreatedAt
	return l, version, nil
}

// UpdateList replaces name, kind, description and entries. A list that a
// policy refers to keeps its name and kind (ErrConflict otherwise).
func (d *DB) UpdateList(ctx context.Context, l List, by string) (uint64, error) {
	entries, _ := json.Marshal(l.Entries)
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		var oldName, oldKind string
		if err := tx.QueryRowContext(ctx, `SELECT name, kind FROM lists WHERE id = ?`, l.ID).Scan(&oldName, &oldKind); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if oldName != l.Name || oldKind != l.Kind {
			if used, err := listUsed(ctx, tx, oldName); err != nil {
				return err
			} else if used {
				return fmt.Errorf("%w: policies refer to list %q; remove those references first", ErrConflict, oldName)
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE lists SET name = ?, kind = ?, description = ?, entries_json = ?, updated_at = ?, updated_by = ? WHERE id = ?`,
			l.Name, l.Kind, l.Description, string(entries), now(), by, l.ID)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return err
	})
}

// DeleteList removes a list no policy refers to.
func (d *DB) DeleteList(ctx context.Context, id string) (uint64, error) {
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM lists WHERE id = ?`, id).Scan(&name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if used, err := listUsed(ctx, tx, name); err != nil {
			return err
		} else if used {
			return fmt.Errorf("%w: policies refer to list %q; remove those references first", ErrConflict, name)
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM lists WHERE id = ?`, id)
		return err
	})
}

// listUsed reports whether any policy names the list.
func listUsed(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies WHERE instr(cedar, ?) > 0`, ListRef(name)).Scan(&n)
	return n > 0, err
}

// ListRef is how Cedar names a list.
func ListRef(name string) string { return `BoundGate::List::"` + name + `"` }
