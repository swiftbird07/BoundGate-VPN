package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
)

// The bootstrap token goes to a file only its owner can read, never to a
// log, also when the file was there before with wider permissions.
func TestBootstrapTokenFile(t *testing.T) {
	dir := t.TempDir()
	if p := bootstrapTokenPath(filepath.Join(dir, "control.db"), ""); p != filepath.Join(dir, "bootstrap-token") {
		t.Fatalf("default path: %s", p)
	}
	if p := bootstrapTokenPath(filepath.Join(dir, "control.db"), "/etc/x"); p != "/etc/x" {
		t.Fatalf("configured path: %s", p)
	}
	path := filepath.Join(dir, "tok")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(path, "bgboot_x"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	b, _ := os.ReadFile(path)
	if st.Mode().Perm() != 0o600 || string(b) != "bgboot_x\n" {
		t.Fatalf("mode %v content %q", st.Mode().Perm(), b)
	}
}

// R12: after the only passkey was lost, the operator of the control-plane
// host rotates the bootstrap token and revokes the passkeys, so that the
// new token works.
func TestRotateBootstrapToken(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	dbPath := filepath.Join(dir, "control.db")
	store, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	old, _, _ := store.EnsureBootstrapToken(ctx)
	if _, err := store.AddPasskey(ctx, db.Passkey{Subject: "alice", Credential: []byte(`{}`), CredentialID: []byte{1}, Status: "active"}, "alice"); err != nil {
		t.Fatal(err)
	}
	store.Close()

	file, revoked, active, err := RotateBootstrapToken(ctx, dbPath, "", false)
	if err != nil || revoked != 0 || active != 1 || file != filepath.Join(dir, "bootstrap-token") {
		t.Fatalf("rotate: %s %d %d %v", file, revoked, active, err)
	}
	if _, revoked, active, err = RotateBootstrapToken(ctx, dbPath, "", true); err != nil || revoked != 1 || active != 0 {
		t.Fatalf("rotate and revoke: %d %d %v", revoked, active, err)
	}
	b, _ := os.ReadFile(file)
	store, _ = db.Open(ctx, dbPath)
	defer store.Close()
	if ok, _ := store.CheckBootstrapToken(ctx, strings.TrimSpace(string(b))); !ok {
		t.Fatal("the written token does not check")
	}
	if ok, _ := store.CheckBootstrapToken(ctx, old); ok {
		t.Fatal("the old token still checks")
	}
	evs, _ := store.ListLogs(ctx, db.LogQuery{Stream: "admin-auth"})
	if len(evs) != 2 || evs[0].Message != "bootstrap token rotated" {
		t.Fatalf("audit: %+v", evs)
	}
}
