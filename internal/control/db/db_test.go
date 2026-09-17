package db

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

func open(t *testing.T) *DB {
	t.Helper()
	d, err := Open(context.Background(), filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

var pool = netip.MustParsePrefix("10.21.0.0/24")

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	ctx := context.Background()
	d1, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	d1.Close()
	d2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	v, err := d2.SnapshotVersion(ctx)
	if err != nil || v != 1 {
		t.Fatalf("version %d %v", v, err)
	}
}

// approve confirms with the grant, mints a token and stores a (fake, the
// api verifies it) signature. It mirrors the confirm -> sign flow.
func approve(t *testing.T, d *DB, id string, g Grant) (uint64, error) {
	t.Helper()
	ctx := context.Background()
	if err := d.ConfirmNode(ctx, id, "admin", g, pool); err != nil {
		return 0, err
	}
	n, _ := d.NodeByID(ctx, id)
	tok, _, err := d.CreateSignToken(ctx, id, n.SPKI, "admin")
	if err != nil {
		return 0, err
	}
	return d.ApproveSigned(ctx, id, tok, `{"binding":true}`, "-----BEGIN SSH SIGNATURE-----", "SHA256:x")
}

func TestNodeLifecycleBumpsSnapshot(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	var spki devicekey.SPKIHash
	spki[0] = 7
	lan := registry.Prefix{Prefix: netip.MustParsePrefix("192.168.178.0/24"), Mode: registry.ModeSNAT}
	n, err := d.CreatePending(ctx, EnrollRequest{Name: "mbp", Platform: "darwin", KeyKind: "softkey", SPKI: spki, CertDER: []byte{1}, RequestIP: "1.2.3.4",
		Roles: []registry.Role{registry.RoleEndpoint, registry.RoleSubnetRouter}, Prefixes: []registry.Prefix{lan}})
	if err != nil {
		t.Fatal(err)
	}
	if n.Status != StatusPending || n.SPKI != spki || len(n.RequestedRoles) != 2 || len(n.RequestedPrefixes) != 1 || len(n.Roles) != 0 || n.KeyVersion != 1 {
		t.Fatalf("%+v", n)
	}
	if _, err := d.CreatePending(ctx, EnrollRequest{SPKI: spki, CertDER: []byte{1}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key: %v", err)
	}
	v0, _ := d.SnapshotVersion(ctx)
	if _, err := d.RevokeNode(ctx, n.ID, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking a pending node must fail: %v", err)
	}
	// prefixes without a router role are refused
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Roles: []registry.Role{registry.RoleEndpoint}, Prefixes: []registry.Prefix{lan}}, pool); !errors.Is(err, ErrConflict) {
		t.Fatalf("prefixes without router role: %v", err)
	}
	// confirm: grant stored, overlay assigned, not in snapshots, no bump
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Name: "mbp-renamed", Roles: n.RequestedRoles, Prefixes: n.RequestedPrefixes}, pool); err != nil {
		t.Fatal(err)
	}
	got, _ := d.NodeBySPKI(ctx, spki)
	if got.Status != StatusConfirmed || got.Name != "mbp-renamed" || got.ConfirmedBy != "admin" || got.OverlayIP != netip.MustParseAddr("10.21.0.1") || len(got.Roles) != 2 || got.Prefixes[0] != lan {
		t.Fatalf("%+v", got)
	}
	if v, _ := d.SnapshotVersion(ctx); v != v0 {
		t.Fatal("confirm bumped the version")
	}
	if approved, _ := d.ApprovedNodes(ctx); len(approved) != 0 {
		t.Fatal("confirmed node in snapshots")
	}
	// confirm again keeps the overlay address; a new grant replaces the old
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Roles: []registry.Role{registry.RoleEndpoint}}, pool); err != nil {
		t.Fatal(err)
	}
	if got, _ = d.NodeByID(ctx, n.ID); got.OverlayIP != netip.MustParseAddr("10.21.0.1") || len(got.Roles) != 1 {
		t.Fatalf("%+v", got)
	}
	// sign token: single use, bound to the node's key
	tok, exp, err := d.CreateSignToken(ctx, n.ID, spki, "admin")
	if err != nil || !exp.After(time.Now().Add(9*time.Minute)) {
		t.Fatal(err, exp)
	}
	st, err := d.LookupSignToken(ctx, tok)
	if err != nil || st.NodeID != n.ID || st.SPKI != spki || st.Admin != "admin" {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := d.LookupSignToken(ctx, "bgsign_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	v1, err := d.ApproveSigned(ctx, n.ID, tok, `{"b":1}`, "sig", "SHA256:k")
	if err != nil || v1 != v0+1 {
		t.Fatalf("approve %d %v", v1, err)
	}
	if _, err := d.LookupSignToken(ctx, tok); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("used token: %v", err)
	}
	if _, err := d.ApproveSigned(ctx, n.ID, tok, `{"b":1}`, "sig", "SHA256:k"); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("token reuse: %v", err)
	}
	got, _ = d.NodeByID(ctx, n.ID)
	if got.Status != StatusApproved || got.Binding != `{"b":1}` || got.Signature != "sig" || got.SignedBy != "SHA256:k" || got.ApprovedBy != "SHA256:k" || got.SignedAt.IsZero() {
		t.Fatalf("%+v", got)
	}
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Roles: got.Roles}, pool); !errors.Is(err, ErrConflict) {
		t.Fatalf("confirm of approved node: %v", err)
	}
	// second node gets the next address; explicit address must be free
	var spki2 devicekey.SPKIHash
	spki2[0] = 8
	n2, _ := d.CreatePending(ctx, EnrollRequest{SPKI: spki2, CertDER: []byte{1}})
	if _, err := approve(t, d, n2.ID, Grant{Roles: []registry.Role{registry.RoleHub}, OverlayIP: netip.MustParseAddr("10.21.0.1")}); !errors.Is(err, ErrConflict) {
		t.Fatalf("taken overlay ip accepted: %v", err)
	}
	if _, err := approve(t, d, n2.ID, Grant{Roles: []registry.Role{registry.RoleHub}, PublicAddr: "hub:443"}); err != nil {
		t.Fatal(err)
	}
	got2, _ := d.NodeByID(ctx, n2.ID)
	if got2.OverlayIP != netip.MustParseAddr("10.21.0.2") || got2.PublicAddr != "hub:443" {
		t.Fatalf("%+v", got2)
	}
	approved, _ := d.ApprovedNodes(ctx)
	if len(approved) != 2 {
		t.Fatalf("approved %d", len(approved))
	}
	// unsigned fields: update bumps, keeps the approval
	v2, demoted, err := d.UpdateNode(ctx, n2.ID, Grant{PublicAddr: "hub.example:443"}, pool)
	if err != nil || demoted || v2 <= v1 {
		t.Fatalf("update %d %v demoted %v (v1 %d)", v2, err, demoted, v1)
	}
	// signed fields: the node drops back to confirmed and out of snapshots
	v3, demoted, err := d.UpdateNode(ctx, n2.ID, Grant{Roles: []registry.Role{registry.RoleHub, registry.RoleExitNode}, Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Mode: registry.ModeSNAT}}}, pool)
	if err != nil || !demoted || v3 != v2+1 {
		t.Fatalf("update %d %v demoted %v", v3, err, demoted)
	}
	got2, _ = d.NodeByID(ctx, n2.ID)
	if got2.Status != StatusConfirmed || got2.Signature != "" || got2.OverlayIP != netip.MustParseAddr("10.21.0.2") {
		t.Fatalf("%+v", got2)
	}
	if approved, _ = d.ApprovedNodes(ctx); len(approved) != 1 {
		t.Fatal("demoted node still in snapshots")
	}
	v4, err := d.RevokeNode(ctx, n.ID, "admin")
	if err != nil || v4 != v3+1 {
		t.Fatalf("revoke %d %v", v4, err)
	}
	if approved, _ = d.ApprovedNodes(ctx); len(approved) != 0 {
		t.Fatal("revoked node still approved")
	}
	// the freed address is reusable, a revoked key can never come back
	var spki3 devicekey.SPKIHash
	spki3[0] = 9
	n3, _ := d.CreatePending(ctx, EnrollRequest{SPKI: spki3, CertDER: []byte{1}})
	if _, err := approve(t, d, n3.ID, Grant{Roles: []registry.Role{registry.RoleEndpoint}}); err != nil {
		t.Fatal(err)
	}
	if got3, _ := d.NodeByID(ctx, n3.ID); got3.OverlayIP != netip.MustParseAddr("10.21.0.1") {
		t.Fatalf("freed address not reused: %s", got3.OverlayIP)
	}
	if _, err := d.CreatePending(ctx, EnrollRequest{SPKI: spki, CertDER: []byte{1}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-enroll revoked key: %v", err)
	}
}

func TestSigners(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	if ss, _ := d.ListSigners(ctx, true); len(ss) != 0 {
		t.Fatal(ss)
	}
	s, err := d.AddSigner(ctx, Signer{Subject: "bootstrap", Name: "martin yubikey", PublicKey: "sk-ssh-ed25519@openssh.com AAAA", KeyType: "sk-ssh-ed25519@openssh.com", Hardware: true, Fingerprint: "SHA256:a"})
	if err != nil || s.ID == "" || !s.Hardware || s.AuthorizedKey() != "sk-ssh-ed25519@openssh.com AAAA martin_yubikey" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := d.AddSigner(ctx, Signer{PublicKey: "sk-ssh-ed25519@openssh.com AAAA"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key: %v", err)
	}
	s2, _ := d.AddSigner(ctx, Signer{PublicKey: "ssh-ed25519 BBBB", KeyType: "ssh-ed25519", Fingerprint: "SHA256:b"})
	if err := d.RevokeSigner(ctx, s2.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeSigner(ctx, s2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke: %v", err)
	}
	active, _ := d.ListSigners(ctx, true)
	all, _ := d.ListSigners(ctx, false)
	if len(active) != 1 || len(all) != 2 || active[0].ID != s.ID || all[1].RevokedAt.IsZero() {
		t.Fatalf("%+v %+v", active, all)
	}
}

func TestRejectAndExpirePending(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	var a, b devicekey.SPKIHash
	a[0], b[0] = 1, 2
	na, _ := d.CreatePending(ctx, EnrollRequest{SPKI: a, CertDER: []byte{1}})
	if _, err := d.CreatePending(ctx, EnrollRequest{SPKI: b, CertDER: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := d.RejectNode(ctx, na.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.NodeByID(ctx, na.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rejected node still exists")
	}
	n, err := d.ExpirePending(ctx, -time.Hour) // everything is "older" than now+1h
	if err != nil || n != 1 {
		t.Fatalf("expired %d %v", n, err)
	}
}

func TestBootstrapToken(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	tok, created, err := d.EnsureBootstrapToken(ctx)
	if err != nil || !created || tok == "" {
		t.Fatalf("bootstrap: %q %v %v", tok, created, err)
	}
	if _, created, _ := d.EnsureBootstrapToken(ctx); created {
		t.Fatal("bootstrap token recreated")
	}
	if ok, _ := d.CheckBootstrapToken(ctx, tok); !ok {
		t.Fatal("bootstrap token rejected")
	}
	if ok, _ := d.CheckBootstrapToken(ctx, tok+"x"); ok {
		t.Fatal("wrong bootstrap token accepted")
	}
}

func TestNetworkSettingsAndLogs(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	n, err := d.Network(ctx)
	if err != nil || n.Pool != DefaultNetwork.Pool {
		t.Fatalf("default network %+v %v", n, err)
	}
	v0, _ := d.SnapshotVersion(ctx)
	want := NetworkSettings{Pool: netip.MustParsePrefix("100.64.0.0/20")}
	v1, err := d.PutSetting(ctx, SettingNetwork, want, "admin", true)
	if err != nil || v1 != v0+1 {
		t.Fatalf("put %d %v", v1, err)
	}
	n, _ = d.Network(ctx)
	if n.Pool != want.Pool {
		t.Fatalf("%+v", n)
	}
	if err := (NetworkSettings{Pool: netip.MustParsePrefix("100.64.0.1/20")}).Validate(); err == nil {
		t.Fatal("pool with host bits accepted")
	}

	d.InsertLog(ctx, LogEvent{Stream: "audit", Actor: "admin", DeviceID: "dev1", Message: "approved node", Attrs: map[string]any{"name": "mbp"}})
	d.InsertLog(ctx, LogEvent{Stream: "system", Message: "started"})
	evs, err := d.ListLogs(ctx, LogQuery{Stream: "audit"})
	if err != nil || len(evs) != 1 || evs[0].DeviceID != "dev1" || evs[0].Attrs["name"] != "mbp" {
		t.Fatalf("%+v %v", evs, err)
	}
	evs, _ = d.ListLogs(ctx, LogQuery{Text: "start"})
	if len(evs) != 1 || evs[0].Stream != "system" {
		t.Fatalf("%+v", evs)
	}
}

func TestPoliciesAndTunnels(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	p, v1, err := d.CreatePolicy(ctx, Policy{Name: "all", Cedar: "permit(principal, action, resource);", Enabled: true}, "admin")
	if err != nil || p.ID == "" || v1 == 0 {
		t.Fatal(err, v1)
	}
	if _, _, err := d.CreatePolicy(ctx, Policy{Name: "all", Cedar: "x"}, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	q, _, err := d.CreatePolicy(ctx, Policy{Name: "scoped", Cedar: "forbid(principal, action, resource);", Enabled: false, Scope: []string{"n1"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if ps, _ := d.EnabledPolicies(ctx); len(ps) != 1 || ps[0].ID != p.ID {
		t.Fatalf("enabled: %+v", ps)
	}
	q.Enabled = true
	if _, err := d.UpdatePolicy(ctx, q, "admin"); err != nil {
		t.Fatal(err)
	}
	ps, _ := d.EnabledPolicies(ctx)
	if len(ps) != 2 || !ps[1].AppliesTo("n1") || ps[1].AppliesTo("n2") || !ps[0].AppliesTo("n2") {
		t.Fatalf("scope: %+v", ps)
	}
	if _, err := d.DeletePolicy(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := d.DeletePolicy(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PolicyByID(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted policy still there")
	}

	opened := time.Now().Add(-time.Hour)
	if err := d.UpsertTunnel(ctx, TunnelReport{ID: "t1", HubID: "h", PeerID: "p", OpenedAt: opened, BytesIn: 10}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertTunnel(ctx, TunnelReport{ID: "t1", HubID: "h", PeerID: "p", OpenedAt: opened, BytesIn: 5, BytesOut: 7}); err != nil {
		t.Fatal(err)
	}
	ts, err := d.ListTunnels(ctx, TunnelQuery{Active: true})
	if err != nil || len(ts) != 1 || ts[0].BytesIn != 10 || ts[0].BytesOut != 7 {
		t.Fatalf("%v %+v", err, ts)
	}
	if n, _ := d.CloseStaleTunnels(ctx, time.Hour); n != 0 {
		t.Fatal("fresh tunnel closed as stale")
	}
	if n, _ := d.CloseStaleTunnels(ctx, -time.Second); n != 1 {
		t.Fatal("stale tunnel not closed")
	}
	ts, _ = d.ListTunnels(ctx, TunnelQuery{})
	if ts[0].ClosedAt == nil || ts[0].CloseReason != "hub stopped reporting" {
		t.Fatalf("%+v", ts[0])
	}
	// the hub reports again (it was only silent): the tunnel is open again
	if err := d.UpsertTunnel(ctx, TunnelReport{ID: "t1", HubID: "h", PeerID: "p", OpenedAt: opened, BytesIn: 20}); err != nil {
		t.Fatal(err)
	}
	if ts, _ = d.ListTunnels(ctx, TunnelQuery{Active: true}); len(ts) != 1 || ts[0].CloseReason != "" || ts[0].BytesIn != 20 {
		t.Fatalf("not reopened: %+v", ts)
	}
	// a real close stays closed, whatever arrives later
	closedAt := time.Now()
	d.UpsertTunnel(ctx, TunnelReport{ID: "t1", HubID: "h", PeerID: "p", OpenedAt: opened, ClosedAt: closedAt, CloseReason: "closed by peer"})
	d.UpsertTunnel(ctx, TunnelReport{ID: "t1", HubID: "h", PeerID: "p", OpenedAt: opened, BytesIn: 30})
	if ts, _ = d.ListTunnels(ctx, TunnelQuery{}); ts[0].ClosedAt == nil || ts[0].CloseReason != "closed by peer" {
		t.Fatalf("closed tunnel reopened: %+v", ts[0])
	}
	if n, _ := d.PruneTunnels(ctx, -time.Second); n != 1 {
		t.Fatal("prune")
	}
}

// Stored timestamps must sort as strings the way they sort as times.
func TestTimeFormatSortsLexically(t *testing.T) {
	base := time.Date(2026, 9, 17, 12, 0, 5, 0, time.UTC)
	a, b := base.Add(100*time.Millisecond), base.Add(150*time.Millisecond)
	if !(a.Format(timeFormat) < b.Format(timeFormat)) {
		t.Fatalf("%s !< %s", a.Format(timeFormat), b.Format(timeFormat))
	}
	if a.Format(time.RFC3339Nano) < b.Format(time.RFC3339Nano) {
		t.Fatal("RFC3339Nano sorts correctly now? revisit timeFormat")
	}
	if got := parseTime(sql.NullString{String: a.Format(timeFormat), Valid: true}); !got.Equal(a) {
		t.Fatalf("round trip: %v", got)
	}
}
