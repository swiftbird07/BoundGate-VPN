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
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB wraps the SQLite connection.
type DB struct {
	sql *sql.DB
}

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
	return d, nil
}

// Close closes the connection.
func (d *DB) Close() error { return d.sql.Close() }

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

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

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
