// Package db is the control plane's SQLite store. It owns the schema
// (embedded migrations) and exposes typed operations; handlers never write
// SQL. Every mutation that changes what gateways must know bumps the
// snapshot version inside the same transaction.
package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB wraps the SQLite connections: one writer and, beside it, a read-only
// pool. Everything that changes the database goes through sql, which is a
// single connection; queries that only read go through ro, which has
// several. A node's lookup at the TLS handshake therefore no longer waits
// behind an admin page's query or behind housekeeping.
type DB struct {
	sql *sql.DB
	ro  *sql.DB
	// logCols is the lowest log_events id whose hot attribute columns are
	// filled (migration 0018). Rows below it still need json_extract until
	// housekeeping has worked its way down. It only ever decreases, so a
	// stale value costs a slower query, never a wrong answer.
	logCols atomic.Int64
}

// readers is how many connections may read at once. WAL readers do not block
// each other or the writer; the number only bounds how much work the admin UI
// and the janitor can ask of the disk in parallel.
const readers = 4

// Open opens (creating if needed) the database and applies migrations.
func Open(ctx context.Context, path string) (*DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	s, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	// SQLite handles one writer at a time; a single connection avoids
	// SQLITE_BUSY dances for a control plane of this size.
	s.SetMaxOpenConns(1)
	d := &DB{sql: s}
	if err := d.migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	// mode=ro keeps a mistake from becoming a write: the file is there and
	// in WAL mode by now, so these connections only ever read it.
	ro, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("db: open for reading: %w", err)
	}
	ro.SetMaxOpenConns(readers)
	ro.SetMaxIdleConns(readers)
	if err := ro.PingContext(ctx); err != nil {
		ro.Close()
		s.Close()
		return nil, fmt.Errorf("db: open for reading: %w", err)
	}
	d.ro = ro
	d.logCols.Store(d.readWatermark(ctx))
	return d, nil
}

// read is the pool for queries that only read. It falls back to the writer
// when there is no read pool, so a DB built another way still works.
func (d *DB) read() *sql.DB {
	if d.ro != nil {
		return d.ro
	}
	return d.sql
}

// Close closes both connections.
func (d *DB) Close() error {
	if d.ro != nil {
		d.ro.Close()
	}
	return d.sql.Close()
}

func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.sql.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("db: migrations table: %w", err)
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for i, name := range names {
		version := i + 1
		var applied int
		if err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := d.sql.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("db: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, now()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("db: not found")

// ErrConflict is returned when a unique constraint or state check fails.
var ErrConflict = errors.New("db: conflict")

// timeFormat is RFC 3339 with a fixed nine-digit fraction. Timestamps are
// compared as strings in SQL (expiry, retention, cursors); time.RFC3339Nano
// trims trailing zeros, which makes "…05.1Z" sort after "…05.15Z".
const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"

func now() string { return time.Now().UTC().Format(timeFormat) }

func parseTime(s sql.NullString) time.Time {
	if !s.Valid || s.String == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, s.String)
	return t
}

// NewID returns a random 128-bit hex identifier.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// NewToken returns a random secret with the given prefix and its hash.
func NewToken(prefix string) (token string, hash []byte) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	token = prefix + "_" + hex.EncodeToString(b[:])
	h := sha256.Sum256([]byte(token))
	return token, h[:]
}

// HashToken hashes a presented token for lookup.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return h[:]
}

func hashEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// tx runs fn in a transaction that also bumps the snapshot version when
// bump is true.
func (d *DB) tx(ctx context.Context, bump bool, fn func(tx *sql.Tx) error) (uint64, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return 0, err
	}
	var version uint64
	if bump {
		if _, err := tx.ExecContext(ctx, `UPDATE snapshot_version SET version = version + 1, updated_at = ?`, now()); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT version FROM snapshot_version`).Scan(&version); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version, nil
}

// SnapshotVersion returns the current registry version.
func (d *DB) SnapshotVersion(ctx context.Context) (uint64, error) {
	var v uint64
	err := d.sql.QueryRowContext(ctx, `SELECT version FROM snapshot_version`).Scan(&v)
	return v, err
}
