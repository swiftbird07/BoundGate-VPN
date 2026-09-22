package node

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentIsRememberedAcrossStarts(t *testing.T) {
	dir := t.TempDir()
	if _, ok := loadEnrollment(dir); ok {
		t.Fatal("nothing saved yet")
	}
	n := &Node{cfg: Config{StateDir: dir}, log: slog.Default()}
	n.status.Enrollment, n.status.NodeID = "approved", "1e88550024ade41f33999cc0a545cb01"
	n.saveEnrollment()
	e, ok := loadEnrollment(dir)
	if !ok || e.Status != "approved" || e.NodeID != "1e88550024ade41f33999cc0a545cb01" {
		t.Fatalf("saved %+v %v", e, ok)
	}
	n.status.Enrollment = "revoked"
	n.saveEnrollment()
	if e, _ := loadEnrollment(dir); e.Status != "revoked" {
		t.Fatalf("revoked not saved: %+v", e)
	}
	_ = os.WriteFile(filepath.Join(dir, enrollmentFile), []byte(`{"status":"whatever"}`), 0o600)
	if _, ok := loadEnrollment(dir); ok {
		t.Fatal("an unknown state is not taken")
	}
}
