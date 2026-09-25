package db

import (
	"context"
	"testing"
	"time"
)

// What unauthenticated or routine requests leave behind is deleted by the
// housekeeping loop: expired admin login flows, admin sessions that ended a
// day ago, user sessions older than the retention.
func TestJanitorDeletesWhatExpired(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-48 * time.Hour).Format(timeFormat)
	count := func(table string) int {
		var n int
		if err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	stale, _ := d.CreateAdminLoginFlow(ctx, "s1", "n", "v", "/")
	if _, err := d.CreateAdminLoginFlow(ctx, "s2", "n", "v", "/"); err != nil {
		t.Fatal(err)
	}
	_, _ = d.sql.ExecContext(ctx, `UPDATE admin_login_flows SET expires_at = ? WHERE id = ?`, old, stale.ID)
	if n, _ := d.CountPendingAdminLoginFlows(ctx); n != 1 {
		t.Fatalf("pending admin flows: %d", n)
	}
	gone, _ := d.CreateAdminSession(ctx, AdminSession{Subject: "a"}, time.Hour)
	if _, err := d.CreateAdminSession(ctx, AdminSession{Subject: "b"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, _ = d.sql.ExecContext(ctx, `UPDATE admin_sessions SET expires_at = ? WHERE id = ?`, old, gone.ID)
	if err := d.ExpireAdminSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if count("admin_login_flows") != 1 || count("admin_sessions") != 1 {
		t.Fatalf("after the sweep: %d flows, %d sessions", count("admin_login_flows"), count("admin_sessions"))
	}

	var spki [32]byte
	spki[0] = 5
	n, _ := d.CreatePending(ctx, EnrollRequest{SPKI: spki, CertDER: []byte{1}})
	_, _ = d.sql.ExecContext(ctx, `INSERT INTO user_sessions (id, node_id, subject, issued_at, expires_at, revoked_at, revoked_by, end_reason) VALUES
		('old', ?, 'u', ?, ?, ?, 'system', 'expired'), ('new', ?, 'u', ?, ?, ?, 'system', 'expired'), ('live', ?, 'u', ?, ?, NULL, NULL, '')`,
		n.ID, old, old, old, n.ID, now(), now(), now(), n.ID, now(), time.Now().UTC().Add(time.Hour).Format(timeFormat))
	if pruned, err := d.PruneSessions(ctx, 24*time.Hour); err != nil || pruned != 1 || count("user_sessions") != 2 {
		t.Fatalf("prune sessions: %d %v, left %d", pruned, err, count("user_sessions"))
	}
}
