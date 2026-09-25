package db

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// public_addr makes every peer route the address around the overlay, so
// what a node sends at enrollment is only a request: the address in effect
// is what an admin sets.
func TestPublicAddrIsTheAdminsAlone(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	var spki devicekey.SPKIHash
	spki[0] = 1
	n, err := d.CreatePending(ctx, EnrollRequest{SPKI: spki, CertDER: []byte{1}, PublicAddr: "169.254.169.254:80"})
	if err != nil {
		t.Fatal(err)
	}
	if n.PublicAddr != "" || n.RequestedPublicAddr != "169.254.169.254:80" {
		t.Fatalf("pending: public %q requested %q", n.PublicAddr, n.RequestedPublicAddr)
	}
	if _, err := approve(t, d, n.ID, Grant{Roles: []registry.Role{registry.RoleHub}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.NodeByID(ctx, n.ID); got.PublicAddr != "" {
		t.Fatalf("the request was taken over: %q", got.PublicAddr)
	}

	spki[0] = 2
	n2, _ := d.CreatePending(ctx, EnrollRequest{SPKI: spki, CertDER: []byte{1}, PublicAddr: "evil:1"})
	if err := d.ConfirmNode(ctx, n2.ID, "admin", Grant{Roles: []registry.Role{registry.RoleHub}, PublicAddr: ptr("hub.example.com:443")}, pool); err != nil {
		t.Fatal(err)
	}
	// confirming again without the field keeps the admin's address, "" clears it
	if err := d.ConfirmNode(ctx, n2.ID, "admin", Grant{Roles: []registry.Role{registry.RoleHub}}, pool); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.NodeByID(ctx, n2.ID); got.PublicAddr != "hub.example.com:443" {
		t.Fatalf("confirm again: %q", got.PublicAddr)
	}
	if err := d.ConfirmNode(ctx, n2.ID, "admin", Grant{Roles: []registry.Role{registry.RoleHub}, PublicAddr: ptr("")}, pool); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.NodeByID(ctx, n2.ID); got.PublicAddr != "" {
		t.Fatalf("cleared at confirm: %q", got.PublicAddr)
	}
	if err := d.ConfirmNode(ctx, n2.ID, "admin", Grant{Roles: []registry.Role{registry.RoleHub}, PublicAddr: ptr("hub.example.com")}, pool); !errors.Is(err, ErrConflict) {
		t.Fatalf("an address without a port: %v", err)
	}
}

func TestCleanPublicAddr(t *testing.T) {
	for _, ok := range []string{"hub1:443", "hub.example.com:443", "bg.test:443", "172.30.0.40:4443", "[2001:db8::1]:443", " hub:1 ", "h_1.example.:65535"} {
		if _, err := CleanPublicAddr(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "hub", "hub:", ":443", "hub:0", "hub:65536", "hub:0443", "hub:-1", "https://hub:443", "hub:443/x", "hub/x:443",
		"user@hub:443", "2001:db8::1:443", "[hub]:443", "[fe80::1%eth0]:443", "[::ffff:10.0.0.1]:443", "hub .example:443", "-hub:443", "hub:443?x", "hub\\x:443"} {
		if _, err := CleanPublicAddr(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Asking for the sign command again (confirm of a confirmed node with an
// empty body) must not undo the admin's refusal of a reported hardware key.
func TestConfirmAgainKeepsTheHardwareGrant(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	var spki devicekey.SPKIHash
	spki[0] = 3
	n, _ := d.CreatePending(ctx, EnrollRequest{SPKI: spki, CertDER: []byte{1}, HardwareBound: true})
	roles := []registry.Role{registry.RoleEndpoint}
	// first confirm without the field: the claim is the starting point
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Roles: roles}, pool); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.NodeByID(ctx, n.ID); !got.HardwareBound {
		t.Fatal("first confirm did not take the claim")
	}
	// the admin distrusts it, then asks for a new sign token
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Roles: roles, HardwareBound: ptr(false)}, pool); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Roles: roles}, pool); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.NodeByID(ctx, n.ID); got.HardwareBound {
		t.Fatal("confirming again undid the refusal of hardware_bound")
	}
	// an explicit grant still works
	if err := d.ConfirmNode(ctx, n.ID, "admin", Grant{Roles: roles, HardwareBound: ptr(true)}, pool); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.NodeByID(ctx, n.ID); !got.HardwareBound {
		t.Fatal("explicit grant ignored")
	}
}

// A router prefix that overlaps the overlay pool would pull overlay
// addresses out of the overlay; only a default route may contain the pool.
func TestPrefixesMustNotOverlapThePool(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	var spki devicekey.SPKIHash
	spki[0] = 4
	n, _ := d.CreatePending(ctx, EnrollRequest{SPKI: spki, CertDER: []byte{1}})
	roles := []registry.Role{registry.RoleSubnetRouter, registry.RoleExitNode}
	grant := func(ps ...string) Grant {
		g := Grant{Roles: roles}
		for _, p := range ps {
			g.Prefixes = append(g.Prefixes, registry.Prefix{Prefix: netip.MustParsePrefix(p), Mode: registry.ModeSNAT})
		}
		return g
	}
	for _, bad := range []string{"10.0.0.0/8", "10.21.0.0/28", "10.21.0.128/25", "10.20.0.0/15"} {
		if err := d.ConfirmNode(ctx, n.ID, "admin", grant("192.168.1.0/24", bad), pool); !errors.Is(err, ErrConflict) {
			t.Errorf("%s next to the pool %s accepted: %v", bad, pool, err)
		}
	}
	if err := d.ConfirmNode(ctx, n.ID, "admin", grant("0.0.0.0/0", "10.22.0.0/16", "192.168.1.0/24"), pool); err != nil {
		t.Fatalf("default routes and neighbours: %v", err)
	}
	if _, err := d.ApproveSigned(ctx, n.ID, mustSignToken(t, d, n.ID), `{}`, "sig", "SHA256:k"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.UpdateNode(ctx, n.ID, grant("10.21.0.0/16"), pool); !errors.Is(err, ErrConflict) {
		t.Fatalf("patch into the pool: %v", err)
	}
	// the pool cannot move under a routed prefix either
	nodes, _ := d.ListNodes(ctx, "")
	if clash := PrefixesInPool(nodes, netip.MustParsePrefix("10.22.0.0/24")); len(clash) != 1 {
		t.Fatalf("pool inside a routed prefix: %v", clash)
	}
	if clash := PrefixesInPool(nodes, netip.MustParsePrefix("10.23.0.0/24")); len(clash) != 0 {
		t.Fatalf("pool next to the prefixes: %v", clash)
	}
}

func mustSignToken(t *testing.T, d *DB, id string) string {
	t.Helper()
	n, _ := d.NodeByID(context.Background(), id)
	tok, _, err := d.CreateSignToken(context.Background(), id, n.SPKI, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestPoolMustBePrivate(t *testing.T) {
	for _, ok := range []string{"10.21.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "172.31.5.0/24", "192.168.0.0/16", "100.64.0.0/10", "100.100.0.0/16"} {
		if err := (NetworkSettings{Pool: netip.MustParsePrefix(ok)}).Validate(); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"8.8.0.0/16", "0.0.0.0/0", "10.0.0.0/7", "172.0.0.0/8", "192.0.2.0/24", "100.0.0.0/8", "10.21.0.0/31", "10.21.0.1/16"} {
		if err := (NetworkSettings{Pool: netip.MustParsePrefix(bad)}).Validate(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
