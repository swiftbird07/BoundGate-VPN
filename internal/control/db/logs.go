package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// LogEvent is a row of log_events: a copy of the JSON-line logs that powers
// the admin UI. The files remain the source of truth for the SIEM.
type LogEvent struct {
	ID        int64          `json:"id"`
	TS        time.Time      `json:"ts"`
	Stream    string         `json:"stream"`
	Actor     string         `json:"actor,omitempty"`
	DeviceID  string         `json:"device_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	GatewayID string         `json:"gateway_id,omitempty"`
	Message   string         `json:"message"`
	Attrs     map[string]any `json:"attrs,omitempty"`
}

// InsertLog stores an event. Errors are swallowed on purpose: logging must
// never break the operation being logged (the file stream still has it).
func (d *DB) InsertLog(ctx context.Context, e LogEvent) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	attrs, _ := json.Marshal(e.Attrs)
	if e.Attrs == nil {
		attrs = []byte("{}")
	}
	_, _ = d.sql.ExecContext(ctx, insertLogSQL, logArgs(e, attrs)...)
}

// logCols are the attributes the admin UI filters on. They are columns of
// their own (migration 0018) so that a filter is an index lookup instead of a
// json_extract over the table; attrs_json keeps them as well, as the record.
var logCols = []string{"event", "decision", "principal", "dst", "owner"}

const insertLogSQL = `INSERT INTO log_events (ts, stream, actor, device_id, session_id, gateway_id, message, attrs_json, event, decision, principal, dst, owner)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func logArgs(e LogEvent, attrs []byte) []any {
	args := []any{e.TS.UTC().Format(timeFormat), e.Stream, e.Actor, nullable(e.DeviceID), nullable(e.SessionID), nullable(e.GatewayID), e.Message, string(attrs)}
	for _, k := range logCols {
		v, _ := e.Attrs[k].(string)
		args = append(args, nullable(v))
	}
	return args
}

// LogQuery filters ListLogs.
type LogQuery struct {
	Stream   string
	DeviceID string
	Actor    string
	Since    time.Time
	Until    time.Time
	Text     string
	// Attrs filters on top-level attribute values (json_extract equality).
	Attrs  map[string]string
	Before int64 // cursor: return rows with id < Before
	Limit  int
}

// MaxLogLimit is the most events one query returns. A larger limit is
// clamped to it, not silently turned into the default.
const MaxLogLimit = 1000

// TextWindow is how far back a free-text search goes when the query names no
// start: `message LIKE '%…%'` cannot use an index, so without a window it is
// a scan of every event ever kept.
const TextWindow = 24 * time.Hour

// where builds the condition of a log query. mark is the backfill watermark:
// at or above it the hot attributes are columns, below it they are still
// inside attrs_json.
func (q LogQuery) where(mark int64) (string, []any) {
	hot := map[string]bool{}
	for _, k := range logCols {
		hot[k] = true
	}
	sqlq := ` WHERE 1=1`
	var args []any
	if q.Stream != "" {
		sqlq += ` AND stream = ?`
		args = append(args, q.Stream)
	}
	if q.DeviceID != "" {
		sqlq += ` AND device_id = ?`
		args = append(args, q.DeviceID)
	}
	if q.Actor != "" {
		sqlq += ` AND actor = ?`
		args = append(args, q.Actor)
	}
	if !q.Since.IsZero() {
		sqlq += ` AND ts >= ?`
		args = append(args, q.Since.UTC().Format(timeFormat))
	}
	if !q.Until.IsZero() {
		sqlq += ` AND ts <= ?`
		args = append(args, q.Until.UTC().Format(timeFormat))
	}
	if q.Text != "" {
		sqlq += ` AND (message LIKE ? OR attrs_json LIKE ?)`
		args = append(args, "%"+q.Text+"%", "%"+q.Text+"%")
	}
	for k, v := range q.Attrs {
		if !validAttrKey(k) {
			continue
		}
		switch {
		case hot[k] && mark <= 1:
			sqlq += ` AND ` + k + ` = ?`
			args = append(args, v)
		case hot[k]:
			sqlq += ` AND ((id >= ? AND ` + k + ` = ?) OR (id < ? AND json_extract(attrs_json, '$.` + k + `') = ?))`
			args = append(args, mark, v, mark, v)
		default:
			sqlq += ` AND json_extract(attrs_json, '$.` + k + `') = ?`
			args = append(args, v)
		}
	}
	if q.Before > 0 {
		sqlq += ` AND id < ?`
		args = append(args, q.Before)
	}
	return sqlq, args
}

// prepare clamps the limit and gives a free-text search its time window.
func (q LogQuery) prepare() LogQuery {
	if q.Limit <= 0 {
		q.Limit = 200
	}
	if q.Limit > MaxLogLimit {
		q.Limit = MaxLogLimit
	}
	if q.Text != "" && q.Since.IsZero() {
		until := q.Until
		if until.IsZero() {
			until = time.Now()
		}
		q.Since = until.Add(-TextWindow)
	}
	return q
}

// CountLogs counts the events a query matches, without reading them.
func (d *DB) CountLogs(ctx context.Context, q LogQuery) (int, error) {
	where, args := q.prepare().where(d.logCols.Load())
	var n int
	err := d.read().QueryRowContext(ctx, `SELECT COUNT(*) FROM log_events`+where, args...).Scan(&n)
	return n, err
}

// ListLogs returns events newest first.
func (d *DB) ListLogs(ctx context.Context, q LogQuery) ([]LogEvent, error) {
	q = q.prepare()
	where, args := q.where(d.logCols.Load())
	sqlq := `SELECT id, ts, stream, actor, device_id, session_id, gateway_id, message, attrs_json FROM log_events` + where +
		` ORDER BY id DESC LIMIT ?`
	args = append(args, q.Limit)
	rows, err := d.read().QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEvent
	for rows.Next() {
		var e LogEvent
		var ts, attrs string
		var dev, sess, gw *string
		if err := rows.Scan(&e.ID, &ts, &e.Stream, &e.Actor, &dev, &sess, &gw, &e.Message, &attrs); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		e.DeviceID, e.SessionID, e.GatewayID = deref(dev), deref(sess), deref(gw)
		_ = json.Unmarshal([]byte(attrs), &e.Attrs)
		out = append(out, e)
	}
	return out, rows.Err()
}

// InsertLogs stores a batch in one transaction (shipped node logs).
func (d *DB) InsertLogs(ctx context.Context, evs []LogEvent) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, e := range evs {
		if e.TS.IsZero() {
			e.TS = time.Now().UTC()
		}
		attrs, _ := json.Marshal(e.Attrs)
		if e.Attrs == nil {
			attrs = []byte("{}")
		}
		if _, err := tx.ExecContext(ctx, insertLogSQL, logArgs(e, attrs)...); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func validAttrKey(k string) bool {
	if k == "" || len(k) > 32 {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// pruneBatch is how many events one statement of PruneLogs deletes. The
// control plane has one database connection: between two statements a node's
// lookup gets its turn, so a large backlog (a shorter retention, a first run)
// does not hold the connection for minutes.
const pruneBatch = 5000

// pruneMaxBatches is how many of those batches one call deletes. A backlog is
// worked off over the next minutes instead of in one run, because deleting
// without a pause outruns the checkpoint that folds the write-ahead log back
// into the database: measured on pVPN on 2026-10-22, the first run after the
// retention was shortened wrote 1.6 GB of log in 50 s and filled the disk,
// where the whole database was 7.5 GB. 100 000 events a minute is far more
// than the fleet produces, so in normal operation nothing is capped at all.
const pruneMaxBatches = 20

// PruneLogs deletes events older than maxAge, oldest first, pruneBatch at a
// time and at most pruneMaxBatches per call. After every batch the log is
// folded back into the database; housekeeping calls this once a minute, so a
// backlog shrinks by up to 100 000 events a minute.
func (d *DB) PruneLogs(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(timeFormat)
	var total int64
	for i := 0; i < pruneMaxBatches; i++ {
		res, err := d.sql.ExecContext(ctx, `DELETE FROM log_events WHERE id IN (SELECT id FROM log_events WHERE ts < ? ORDER BY ts LIMIT ?)`, cutoff, pruneBatch)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		total += n
		d.checkpoint(ctx)
		if err != nil || n < pruneBatch {
			return total, err
		}
	}
	return total, nil
}

// checkpoint folds the write-ahead log back into the database and truncates
// the file. SQLite does this on its own once the log passes a threshold, but
// that checkpoint is passive: it gives up as soon as it would have to wait,
// and a run of deletes writes pages faster than they are written back, so
// the log grows without bound. Errors are not the caller's business -- the
// data is committed either way, only the log file stays longer.
func (d *DB) checkpoint(ctx context.Context) {
	_, _ = d.sql.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- the hot columns of old rows -----------------------------------------

// readWatermark reads the backfill mark: the lowest id whose hot columns are
// filled. 1 means every row has them. A database without the table (an older
// one, mid-migration) counts as filled rather than as "scan everything".
func (d *DB) readWatermark(ctx context.Context) int64 {
	var mark int64
	if err := d.sql.QueryRowContext(ctx, `SELECT watermark FROM log_events_backfill WHERE id = 1`).Scan(&mark); err != nil {
		return 1
	}
	return mark
}

// LogColumnsFilled reports whether every event's hot attributes are columns,
// so a query no longer needs json_extract for the old rows.
func (d *DB) LogColumnsFilled() bool { return d.logCols.Load() <= 1 }

// backfillBatch is how many old events one call of BackfillLogColumns fills.
// As with pruneBatch, the point is to let go of the writer between batches so
// a node's lookup gets its turn.
const backfillBatch = 2000

// BackfillLogColumns fills the hot columns of the events that were written
// before they existed, newest first, one batch per call. It reports how many
// rows it filled and whether anything is left; housekeeping calls it until
// nothing is.
func (d *DB) BackfillLogColumns(ctx context.Context) (int64, bool, error) {
	mark := d.logCols.Load()
	if mark <= 1 {
		return 0, true, nil
	}
	sets := make([]string, 0, len(logCols))
	for _, k := range logCols {
		sets = append(sets, k+` = json_extract(attrs_json, '$.`+k+`')`)
	}
	var filled int64
	var lowest int64 = 1
	_, err := d.tx(ctx, false, func(tx *sql.Tx) error {
		var from sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT MIN(id) FROM (SELECT id FROM log_events WHERE id < ? ORDER BY id DESC LIMIT ?)`,
			mark, backfillBatch).Scan(&from); err != nil {
			return err
		}
		if from.Valid {
			lowest = from.Int64
			res, err := tx.ExecContext(ctx, `UPDATE log_events SET `+strings.Join(sets, ", ")+` WHERE id >= ? AND id < ?`, lowest, mark)
			if err != nil {
				return err
			}
			filled, _ = res.RowsAffected()
		}
		// nothing below the mark: pruning took the rest, the backfill is done
		_, err := tx.ExecContext(ctx, `UPDATE log_events_backfill SET watermark = ? WHERE id = 1`, lowest)
		return err
	})
	if err != nil {
		return 0, false, err
	}
	// the same reason as in PruneLogs: an update of this many rows must not
	// be left lying in the write-ahead log
	d.checkpoint(ctx)
	d.logCols.Store(lowest)
	return filled, lowest <= 1, nil
}
