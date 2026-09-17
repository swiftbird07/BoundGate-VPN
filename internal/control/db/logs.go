package db

import (
	"context"
	"encoding/json"
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
	_, _ = d.sql.ExecContext(ctx, `INSERT INTO log_events (ts, stream, actor, device_id, session_id, gateway_id, message, attrs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.Format(timeFormat), e.Stream, e.Actor, nullable(e.DeviceID), nullable(e.SessionID), nullable(e.GatewayID), e.Message, string(attrs))
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

// ListLogs returns events newest first.
func (d *DB) ListLogs(ctx context.Context, q LogQuery) ([]LogEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	sqlq := `SELECT id, ts, stream, actor, device_id, session_id, gateway_id, message, attrs_json FROM log_events WHERE 1=1`
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
		sqlq += ` AND json_extract(attrs_json, '$.` + k + `') = ?`
		args = append(args, v)
	}
	if q.Before > 0 {
		sqlq += ` AND id < ?`
		args = append(args, q.Before)
	}
	sqlq += ` ORDER BY id DESC LIMIT ?`
	args = append(args, q.Limit)
	rows, err := d.sql.QueryContext(ctx, sqlq, args...)
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO log_events (ts, stream, actor, device_id, session_id, gateway_id, message, attrs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.TS.UTC().Format(timeFormat), e.Stream, e.Actor, nullable(e.DeviceID), nullable(e.SessionID), nullable(e.GatewayID), e.Message, string(attrs)); err != nil {
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

// PruneLogs deletes events older than maxAge.
func (d *DB) PruneLogs(ctx context.Context, maxAge time.Duration) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM log_events WHERE ts < ?`, time.Now().UTC().Add(-maxAge).Format(timeFormat))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
