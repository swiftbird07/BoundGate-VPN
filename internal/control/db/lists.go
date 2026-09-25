package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
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
	// A list can follow a URL (a file in a Git repository, a feed): the
	// control plane fetches it every SourceInterval and replaces the
	// entries with what it finds. SourceSecret is an optional value for
	// SourceHeader (a private repository's token) and never leaves the
	// control plane; the rest is shown in the admin UI.
	SourceURL       string
	SourceInterval  time.Duration
	SourceHeader    string
	SourceSecret    string
	SourceETag      string
	SourceFetchedAt time.Time
	SourceStatus    string // empty after a fetch that worked
}

// MinListSourceInterval is the shortest interval a list source may have;
// 0 means the list follows no URL.
const MinListSourceInterval = time.Minute

// CleanListSource checks a list's source and returns it normalized. An
// empty URL clears the source.
func CleanListSource(rawURL string, interval time.Duration, header string) (string, time.Duration, string, error) {
	rawURL = strings.TrimSpace(rawURL)
	header = strings.TrimSpace(header)
	if rawURL == "" {
		return "", 0, "", nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", 0, "", errors.New("source url: an http or https address")
	}
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if interval < MinListSourceInterval {
		return "", 0, "", fmt.Errorf("source interval: at least %s", MinListSourceInterval)
	}
	for _, c := range header {
		if c <= ' ' || c == ':' || c > '~' {
			return "", 0, "", errors.New("source header: a header name")
		}
	}
	return u.String(), interval.Round(time.Second), header, nil
}

// ListKinds are the kinds a list can have. "dynamic" is the access list
// that follows the traffic: names matched however the node sees the
// destination (DNS question, TLS server name, or an address the asking
// device resolved that name to a moment ago) next to plain addresses,
// ranges and ports (docs/ACL.md).
var ListKinds = []string{"ip", "dns", "sni", "dynamic"}

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
// where a leading "*." matches any number of labels. A dynamic list takes
// both: an entry that reads as an address, a prefix, a range or one of
// those with a port (registry.AddrEntry) is kept in its canonical form, the
// rest are names. Empty lines and comments (#) are dropped, duplicates
// removed, the result sorted.
func CleanListEntries(kind string, in []string) ([]string, error) {
	if !slices.Contains(ListKinds, kind) {
		return nil, fmt.Errorf("list kind %q: one of %s", kind, strings.Join(ListKinds, ", "))
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
		if kind == "dynamic" {
			a, ok, err := registry.ParseAddrEntry(e)
			if err != nil {
				return nil, fmt.Errorf("entry %q: %w", e, err)
			}
			if ok {
				out = append(out, a.String())
				continue
			}
		}
		e = strings.ToLower(strings.TrimSuffix(e, "."))
		if len(e) > 253 {
			return nil, fmt.Errorf("entry %q: too long", e)
		}
		labels := strings.Split(e, ".")
		for i, l := range labels {
			if !listNameLabelRe.MatchString(l) || (l == "*" && i != 0) {
				return nil, fmt.Errorf("entry %q: a host name, optionally starting with *.", e)
			}
		}
		if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
			// 10.60.0.300 reads as a host name, and a list would keep it as
			// one for good: no name ends in a number
			return nil, fmt.Errorf("entry %q: a name must not end in a number; as an address it does not parse", e)
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

const listCols = `id, name, kind, description, entries_json, created_at, created_by, updated_at, updated_by,
	source_url, source_interval, source_header, source_secret, source_etag, source_fetched_at, source_status`

func scanList(s scanner) (List, error) {
	var l List
	var entries, created, updated, fetched string
	var interval int64
	if err := s.Scan(&l.ID, &l.Name, &l.Kind, &l.Description, &entries, &created, &l.CreatedBy, &updated, &l.UpdatedBy,
		&l.SourceURL, &interval, &l.SourceHeader, &l.SourceSecret, &l.SourceETag, &fetched, &l.SourceStatus); err != nil {
		return List{}, err
	}
	l.SourceInterval = time.Duration(interval) * time.Second
	if fetched != "" {
		l.SourceFetchedAt = parseTime(sql.NullString{String: fetched, Valid: true})
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
		_, err := tx.ExecContext(ctx, `INSERT INTO lists (`+listCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '')`,
			l.ID, l.Name, l.Kind, l.Description, string(entries), ts, by, ts, by,
			l.SourceURL, int64(l.SourceInterval/time.Second), l.SourceHeader, l.SourceSecret)
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
		// A source that changed starts over: the ETag of the old URL says
		// nothing about the new one, and its error is not this one's.
		var oldURL, oldHeader string
		if err := tx.QueryRowContext(ctx, `SELECT source_url, source_header FROM lists WHERE id = ?`, l.ID).Scan(&oldURL, &oldHeader); err != nil {
			return err
		}
		reset := oldURL != l.SourceURL || oldHeader != l.SourceHeader
		q := `UPDATE lists SET name = ?, kind = ?, description = ?, entries_json = ?, updated_at = ?, updated_by = ?,
			source_url = ?, source_interval = ?, source_header = ?, source_secret = ?`
		args := []any{l.Name, l.Kind, l.Description, string(entries), now(), by,
			l.SourceURL, int64(l.SourceInterval / time.Second), l.SourceHeader, l.SourceSecret}
		if reset {
			q += `, source_etag = '', source_fetched_at = '', source_status = ''`
		}
		q += ` WHERE id = ?`
		args = append(args, l.ID)
		_, err := tx.ExecContext(ctx, q, args...)
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

// ListsDue returns the lists whose source is due for a fetch: never
// fetched, or last fetched more than their interval ago.
func (d *DB) ListsDue(ctx context.Context) ([]List, error) {
	ls, err := d.Lists(ctx)
	if err != nil {
		return nil, err
	}
	out := ls[:0]
	for _, l := range ls {
		if l.SourceURL == "" || l.SourceInterval <= 0 {
			continue
		}
		if l.SourceFetchedAt.IsZero() || time.Since(l.SourceFetchedAt) >= l.SourceInterval {
			out = append(out, l)
		}
	}
	return out, nil
}

// SaveListFetch records what a fetch of a list's source brought. entries nil
// leaves the entries alone (nothing changed, or the fetch failed); status is
// the reason it failed, empty when it worked. The snapshot version comes
// back non-zero only when the entries changed.
func (d *DB) SaveListFetch(ctx context.Context, id string, entries []string, etag, status string) (uint64, error) {
	ts := now()
	mark := func(keepETag bool) (uint64, error) {
		if keepETag && etag == "" { // a failed fetch says nothing about the ETag
			_, err := d.sql.ExecContext(ctx, `UPDATE lists SET source_fetched_at = ?, source_status = ? WHERE id = ?`, ts, status, id)
			return 0, err
		}
		_, err := d.sql.ExecContext(ctx, `UPDATE lists SET source_fetched_at = ?, source_status = ?, source_etag = ? WHERE id = ?`, ts, status, etag, id)
		return 0, err
	}
	if entries == nil {
		return mark(true)
	}
	b, _ := json.Marshal(entries)
	var current string
	if err := d.sql.QueryRowContext(ctx, `SELECT entries_json FROM lists WHERE id = ?`, id).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if current == string(b) { // the file is the same as the list: no new snapshot
		return mark(false)
	}
	return d.tx(ctx, true, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE lists SET entries_json = ?, updated_at = ?, updated_by = 'source', source_fetched_at = ?, source_status = ?, source_etag = ? WHERE id = ?`,
			string(b), ts, ts, status, etag, id)
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
