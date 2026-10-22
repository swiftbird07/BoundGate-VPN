package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
)

// Every admin answer says how long the handler took, where the browser's
// network panel shows it.
func TestAdminAnswersCarryTheirTiming(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/admin/overview", nil)
	req.Header.Set("Authorization", "Bearer "+e.boot)
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", rsp.StatusCode)
	}
	if st := rsp.Header.Get("Server-Timing"); !strings.HasPrefix(st, "handler;dur=") {
		t.Fatalf("Server-Timing %q", st)
	}
}

// The overview counts in the database instead of reading the rows: with more
// denied flows than one query returns it used to stop at the limit.
func TestTheOverviewCountsMoreThanItCouldRead(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const n = db.MaxLogLimit + 200
	evs := make([]db.LogEvent, 0, n)
	for i := 0; i < n; i++ {
		evs = append(evs, db.LogEvent{TS: time.Now().UTC(), Stream: logging.StreamFlow, Message: "deny",
			Attrs: map[string]any{"event": "deny", "decision": "deny", "dst": "10.60.0.10"}})
	}
	if err := e.store.InsertLogs(ctx, evs); err != nil {
		t.Fatal(err)
	}
	var o struct {
		DeniedLast24h int `json:"denied_last_24h"`
	}
	e.adminCall("GET", "/api/v1/admin/overview", "", http.StatusOK, &o)
	if o.DeniedLast24h != n {
		t.Fatalf("denied_last_24h %d, want %d", o.DeniedLast24h, n)
	}
}
