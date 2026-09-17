package db

import (
	"context"
	"database/sql"
	"time"
)

// Tunnel is a row of tunnels: one accepted tunnel between a hub and a peer,
// as reported by the hub. Closed tunnels stay for the connection history.
type Tunnel struct {
	ID          string    `json:"id"`
	HubID       string    `json:"hub_id"`
	HubName     string    `json:"hub_name,omitempty"`
	PeerID      string    `json:"peer_id"`
	PeerName    string    `json:"peer_name,omitempty"`
	PeerAddr    string    `json:"peer_addr,omitempty"`
	OpenedAt    time.Time `json:"opened_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
	CloseReason string    `json:"close_reason,omitempty"`
	BytesIn     uint64    `json:"bytes_in"`
	BytesOut    uint64    `json:"bytes_out"`
	PacketsIn   uint64    `json:"packets_in"`
	PacketsOut  uint64    `json:"packets_out"`
	LastReport  time.Time `json:"last_report_at"`
}

// TunnelReport is what a hub sends for one tunnel (open, update or close).
type TunnelReport struct {
	ID          string
	HubID       string
	PeerID      string
	PeerAddr    string
	OpenedAt    time.Time
	ClosedAt    time.Time // zero while open
	CloseReason string
	BytesIn     uint64
	BytesOut    uint64
	PacketsIn   uint64
	PacketsOut  uint64
}

// UpsertTunnel records or updates a tunnel. Counters only grow; a close
// is final.
// A tunnel that housekeeping closed because its hub fell silent (control
// plane or VM paused) is reopened by the hub's next live report.
func (d *DB) UpsertTunnel(ctx context.Context, r TunnelReport) error {
	var closed any
	if !r.ClosedAt.IsZero() {
		closed = r.ClosedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO tunnels (id, hub_id, peer_id, peer_addr, opened_at, closed_at, close_reason, bytes_in, bytes_out, packets_in, packets_out, last_report_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  peer_addr = CASE WHEN excluded.peer_addr <> '' THEN excluded.peer_addr ELSE peer_addr END,
		  closed_at = CASE WHEN tunnels.close_reason = 'hub stopped reporting' AND excluded.closed_at IS NULL THEN NULL
		                   ELSE COALESCE(tunnels.closed_at, excluded.closed_at) END,
		  close_reason = CASE WHEN tunnels.closed_at IS NULL OR tunnels.close_reason = 'hub stopped reporting' THEN excluded.close_reason ELSE close_reason END,
		  bytes_in = MAX(bytes_in, excluded.bytes_in), bytes_out = MAX(bytes_out, excluded.bytes_out),
		  packets_in = MAX(packets_in, excluded.packets_in), packets_out = MAX(packets_out, excluded.packets_out),
		  last_report_at = excluded.last_report_at`,
		r.ID, r.HubID, r.PeerID, r.PeerAddr, r.OpenedAt.UTC().Format(time.RFC3339Nano), closed, r.CloseReason,
		r.BytesIn, r.BytesOut, r.PacketsIn, r.PacketsOut, now())
	return err
}

// TunnelQuery filters ListTunnels.
type TunnelQuery struct {
	Node   string // hub or peer
	Active bool   // only open tunnels
	Since  time.Time
	Limit  int
}

// ListTunnels returns tunnels newest first with hub and peer names.
func (d *DB) ListTunnels(ctx context.Context, q TunnelQuery) ([]Tunnel, error) {
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 500
	}
	sqlq := `SELECT t.id, t.hub_id, COALESCE(h.name, ''), t.peer_id, COALESCE(p.name, ''), t.peer_addr, t.opened_at, t.closed_at, t.close_reason,
		t.bytes_in, t.bytes_out, t.packets_in, t.packets_out, t.last_report_at
		FROM tunnels t LEFT JOIN nodes h ON h.id = t.hub_id LEFT JOIN nodes p ON p.id = t.peer_id WHERE 1=1`
	var args []any
	if q.Node != "" {
		sqlq += ` AND (t.hub_id = ? OR t.peer_id = ?)`
		args = append(args, q.Node, q.Node)
	}
	if q.Active {
		sqlq += ` AND t.closed_at IS NULL`
	}
	if !q.Since.IsZero() {
		sqlq += ` AND (t.closed_at IS NULL OR t.closed_at >= ?)`
		args = append(args, q.Since.UTC().Format(time.RFC3339Nano))
	}
	sqlq += ` ORDER BY t.opened_at DESC LIMIT ?`
	args = append(args, q.Limit)
	rows, err := d.sql.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tunnel
	for rows.Next() {
		var t Tunnel
		var opened, last string
		var closed sql.NullString
		if err := rows.Scan(&t.ID, &t.HubID, &t.HubName, &t.PeerID, &t.PeerName, &t.PeerAddr, &opened, &closed, &t.CloseReason,
			&t.BytesIn, &t.BytesOut, &t.PacketsIn, &t.PacketsOut, &last); err != nil {
			return nil, err
		}
		t.OpenedAt = parseTime(sql.NullString{String: opened, Valid: true})
		t.LastReport = parseTime(sql.NullString{String: last, Valid: true})
		if closed.Valid {
			c := parseTime(closed)
			t.ClosedAt = &c
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CloseHubTunnels closes every open tunnel of a hub (the hub restarted and
// reports its tunnels afresh).
func (d *DB) CloseHubTunnels(ctx context.Context, hubID, reason string) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE tunnels SET closed_at = last_report_at, close_reason = ? WHERE hub_id = ? AND closed_at IS NULL`, reason, hubID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CloseStaleTunnels marks tunnels closed whose hub stopped reporting
// (crashed hub, lost heartbeat) so the history does not show them open
// forever.
func (d *DB) CloseStaleTunnels(ctx context.Context, maxSilence time.Duration) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE tunnels SET closed_at = last_report_at, close_reason = 'hub stopped reporting' WHERE closed_at IS NULL AND last_report_at < ?`,
		time.Now().UTC().Add(-maxSilence).Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneTunnels deletes closed tunnels older than maxAge.
func (d *DB) PruneTunnels(ctx context.Context, maxAge time.Duration) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM tunnels WHERE closed_at IS NOT NULL AND closed_at < ?`, time.Now().UTC().Add(-maxAge).Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
