package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

func flowEvent(dst, decision, principal string, ts time.Time) LogEvent {
	return LogEvent{TS: ts, Stream: "flow", Message: "open", Attrs: map[string]any{
		"event": "open", "decision": decision, "dst": dst, "principal": principal, "proto": "tcp",
	}}
}

// The five hot attributes are columns from the insert on, and a filter on one
// of them is answered from the column, not from attrs_json.
func TestHotAttributesBecomeColumns(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	d.InsertLog(ctx, flowEvent("10.60.0.10", "allow", "node-a", now))
	d.InsertLog(ctx, flowEvent("10.60.0.11", "deny", "node-b", now))

	var event, decision, dst string
	if err := d.sql.QueryRowContext(ctx, `SELECT event, decision, dst FROM log_events WHERE principal = 'node-b'`).Scan(&event, &decision, &dst); err != nil {
		t.Fatalf("columns of a fresh row: %v", err)
	}
	if event != "open" || decision != "deny" || dst != "10.60.0.11" {
		t.Fatalf("columns %q %q %q", event, decision, dst)
	}
	if !d.LogColumnsFilled() {
		t.Fatal("a fresh database should need no backfill")
	}
	evs, err := d.ListLogs(ctx, LogQuery{Attrs: map[string]string{"decision": "deny"}})
	if err != nil || len(evs) != 1 || evs[0].Attrs["dst"] != "10.60.0.11" {
		t.Fatalf("%+v %v", evs, err)
	}
	// an attribute without a column of its own still works
	if evs, err = d.ListLogs(ctx, LogQuery{Attrs: map[string]string{"proto": "tcp"}}); err != nil || len(evs) != 2 {
		t.Fatalf("json_extract filter: %+v %v", evs, err)
	}
}

// Rows written before the columns existed are found by the same filter while
// the backfill is still working its way down, and by the column afterwards.
func TestTheBackfillFillsOldRowsAndFiltersFindThemMeanwhile(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		d.InsertLog(ctx, flowEvent("10.60.0.10", "deny", "node-a", now))
	}
	// the state a database upgraded on pVPN is in: the rows are there, the
	// columns are not, and the watermark says so
	if _, err := d.sql.ExecContext(ctx, `UPDATE log_events SET event = NULL, decision = NULL, principal = NULL, dst = NULL, owner = NULL`); err != nil {
		t.Fatal(err)
	}
	var max int64
	if err := d.sql.QueryRowContext(ctx, `SELECT MAX(id) FROM log_events`).Scan(&max); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.ExecContext(ctx, `UPDATE log_events_backfill SET watermark = ? WHERE id = 1`, max+1); err != nil {
		t.Fatal(err)
	}
	d.logCols.Store(max + 1)

	if d.LogColumnsFilled() {
		t.Fatal("the watermark says the old rows are not filled")
	}
	evs, err := d.ListLogs(ctx, LogQuery{Attrs: map[string]string{"decision": "deny"}})
	if err != nil || len(evs) != 5 {
		t.Fatalf("below the watermark the filter must read attrs_json: %d %v", len(evs), err)
	}
	if n, err := d.CountLogs(ctx, LogQuery{Attrs: map[string]string{"decision": "deny"}}); err != nil || n != 5 {
		t.Fatalf("count below the watermark: %d %v", n, err)
	}

	filled, done, err := d.BackfillLogColumns(ctx)
	if err != nil || filled != 5 || !done {
		t.Fatalf("backfill %d %v %v", filled, done, err)
	}
	if !d.LogColumnsFilled() {
		t.Fatal("still not filled after the backfill")
	}
	if _, _, err := d.BackfillLogColumns(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM log_events WHERE decision = 'deny'`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("columns after the backfill: %d %v", n, err)
	}
	if evs, err = d.ListLogs(ctx, LogQuery{Attrs: map[string]string{"decision": "deny"}}); err != nil || len(evs) != 5 {
		t.Fatalf("%d %v", len(evs), err)
	}
}

// A free-text search without a start is a scan; it gets a window instead.
func TestFreeTextSearchStaysInsideItsWindow(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	d.InsertLog(ctx, LogEvent{TS: now.Add(-48 * time.Hour), Stream: "system", Message: "the old one"})
	d.InsertLog(ctx, LogEvent{TS: now, Stream: "system", Message: "the new one"})

	evs, err := d.ListLogs(ctx, LogQuery{Text: "one"})
	if err != nil || len(evs) != 1 || evs[0].Message != "the new one" {
		t.Fatalf("%+v %v", evs, err)
	}
	// a start of its own is honoured
	evs, _ = d.ListLogs(ctx, LogQuery{Text: "one", Since: now.Add(-72 * time.Hour)})
	if len(evs) != 2 {
		t.Fatalf("an explicit window: %d", len(evs))
	}
	// without free text nothing is windowed
	evs, _ = d.ListLogs(ctx, LogQuery{Stream: "system"})
	if len(evs) != 2 {
		t.Fatalf("no text, no window: %d", len(evs))
	}
}

// A limit above the maximum is clamped, not dropped to the default.
func TestLimitsAreClampedNotDropped(t *testing.T) {
	if got := (LogQuery{Limit: 99999}).prepare().Limit; got != MaxLogLimit {
		t.Fatalf("log limit %d", got)
	}
	if got := (LogQuery{}).prepare().Limit; got != 200 {
		t.Fatalf("log default %d", got)
	}
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		d.InsertLog(ctx, flowEvent("10.60.0.10", "deny", "node-a", now))
	}
	evs, err := d.ListLogs(ctx, LogQuery{Limit: 2})
	if err != nil || len(evs) != 2 {
		t.Fatalf("%d %v", len(evs), err)
	}
	if n, err := d.CountLogs(ctx, LogQuery{Limit: 2}); err != nil || n != 3 {
		t.Fatalf("the count ignores the limit: %d %v", n, err)
	}
}

// The claim behind the second connection: a device's lookup is answered while
// the writer is busy with something long.
func TestTheLookupIsAnsweredWhileTheWriterIsBusy(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	var spki devicekey.SPKIHash
	spki[0] = 9
	if _, err := d.CreatePending(ctx, EnrollRequest{Name: "mbp", SPKI: spki, CertDER: []byte{1}}); err != nil {
		t.Fatal(err)
	}

	busy, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan struct{})
	var busyErr error
	go func() {
		defer close(done)
		// counts long enough to hold the one writer connection for seconds
		var n int64
		busyErr = d.sql.QueryRowContext(busy, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 1000000000) SELECT COUNT(*) FROM c`).Scan(&n)
	}()
	// give the goroutine the connection before asking
	for i := 0; i < 200 && d.sql.Stats().InUse == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}

	start := time.Now()
	_, err := d.NodeBySPKI(ctx, spki)
	took := time.Since(start)
	// the long query must still be running, or the test proves nothing
	select {
	case <-done:
		t.Skipf("the long query ended before the lookup (%v); nothing is being tested", busyErr)
	default:
	}
	if err != nil {
		t.Fatalf("lookup while the writer is busy: %v", err)
	}
	if took > 2*time.Second {
		t.Fatalf("the lookup waited for the writer: %s", took)
	}
	stop()
	<-done
}

// A retention that was shortened on a database with weeks of events must not
// be one unbounded run: it is capped per call, and the write-ahead log is
// folded back after every batch instead of growing until the disk is full.
func TestPruneLogsIsCappedPerCallAndKeepsTheLogSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.db")
	d, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()

	const extra = 7
	old := time.Now().UTC().Add(-48 * time.Hour)
	evs := make([]LogEvent, 0, pruneBatch*pruneMaxBatches+extra)
	for i := 0; i < pruneBatch*pruneMaxBatches+extra; i++ {
		evs = append(evs, LogEvent{TS: old, Stream: "flow", Message: "open"})
	}
	if err := d.InsertLogs(ctx, evs); err != nil {
		t.Fatal(err)
	}

	n, err := d.PruneLogs(ctx, time.Hour)
	if err != nil || n != pruneBatch*pruneMaxBatches {
		t.Fatalf("first run deleted %d (want %d): %v", n, pruneBatch*pruneMaxBatches, err)
	}
	if wal := size(path + "-wal"); wal > 8<<20 {
		t.Fatalf("the write-ahead log grew to %d bytes; the checkpoint between batches is missing", wal)
	}
	if n, err = d.PruneLogs(ctx, time.Hour); err != nil || n != extra {
		t.Fatalf("second run deleted %d (want %d): %v", n, extra, err)
	}
	var left int
	if err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM log_events`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d events left: %v", left, err)
	}
}

func size(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}
