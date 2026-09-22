package acl

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

func lab(policies ...registry.Policy) *registry.Snapshot {
	s := &registry.Snapshot{
		Version: 1,
		Pool:    netip.MustParsePrefix("10.21.0.0/16"),
		Self: registry.Node{ID: "hub1", Name: "hub1", Kind: registry.KindWorkload, Roles: []registry.Role{registry.RoleHub, registry.RoleSubnetRouter},
			OverlayIP: netip.MustParseAddr("10.21.0.1"), Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("10.60.0.0/24"), Mode: registry.ModeSNAT}}},
		Peers: []registry.Node{
			{ID: "node-a", Name: "node-a", Kind: registry.KindInteractive, Roles: []registry.Role{registry.RoleEndpoint}, OverlayIP: netip.MustParseAddr("10.21.0.2"), HardwareBound: true},
			{ID: "node-r", Name: "node-r", Kind: registry.KindWorkload, Roles: []registry.Role{registry.RoleEndpoint, registry.RoleSubnetRouter}, OverlayIP: netip.MustParseAddr("10.21.0.3"),
				Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.178.0/24"), Mode: registry.ModeSNAT}}},
			{ID: "node-b", Name: "node-b", Kind: registry.KindInteractive, Roles: []registry.Role{registry.RoleEndpoint}, OverlayIP: netip.MustParseAddr("10.21.0.4")},
		},
		Sessions: []registry.Session{
			{ID: "s1", NodeID: "node-a", Subject: "martin", Username: "martin", Email: "m@example.test", Groups: []string{"vpn-users", "admins"}, ExpiresAt: time.Now().Add(time.Hour)},
			{ID: "s2", NodeID: "node-b", Subject: "eve", Username: "eve", Groups: []string{"guests"}, ExpiresAt: time.Now().Add(-time.Minute)}, // expired
		},
		Policies: policies,
	}
	s.Index()
	return s
}

func req(p, dst string, port uint16, proto uint8) Request {
	return Request{Principal: transport.DeviceID(p), Dst: netip.MustParseAddr(dst), Port: port, Proto: proto}
}

func TestDefaultDeny(t *testing.T) {
	e := New(lab())
	if e.Evaluate(req("node-a", "10.60.0.10", 80, 6)).Allow {
		t.Fatal("allowed without policies")
	}
	e = New(lab(registry.Policy{ID: "p1", Name: "all", Cedar: `permit(principal, action, resource);`}))
	if !e.Evaluate(req("node-a", "10.60.0.10", 80, 6)).Allow {
		t.Fatal("permit-all denied")
	}
	if e.Evaluate(req("stranger", "10.60.0.10", 80, 6)).Allow {
		t.Fatal("unknown principal allowed")
	}
}

func TestGroupsRolesNetworks(t *testing.T) {
	e := New(lab(
		registry.Policy{ID: "p-users", Name: "vpn-users reach the LAN", Cedar: `permit(principal in BoundGate::Group::"vpn-users", action, resource in BoundGate::Network::"192.168.178.0/24");`},
		registry.Policy{ID: "p-routers", Name: "routers reach each other", Cedar: `permit(principal in BoundGate::Role::"subnet-router", action, resource in BoundGate::Node::"hub1");`},
		registry.Policy{ID: "p-hw", Name: "hardware keys reach the target", Cedar: `permit(principal, action, resource) when { principal.hardware_bound && resource.ip.isInRange(ip("10.60.0.0/24")) && resource.port == 80 };`},
		registry.Policy{ID: "p-forbid", Name: "never the printer", Cedar: `forbid(principal, action, resource) when { resource.ip == ip("192.168.178.99") };`},
	))
	if len(e.Errors()) != 0 || e.Policies() != 4 {
		t.Fatalf("errors %v policies %d", e.Errors(), e.Policies())
	}
	cases := []struct {
		name string
		r    Request
		want bool
		pol  string
	}{
		{"user in group reaches LAN host", req("node-a", "192.168.178.10", 80, 6), true, "vpn-users reach the LAN"},
		{"forbid wins", req("node-a", "192.168.178.99", 9100, 6), false, "never the printer"},
		{"expired session: not in the group", req("node-b", "192.168.178.10", 80, 6), false, ""},
		{"workload without session: not in the group", req("node-r", "192.168.178.10", 80, 6), false, ""},
		{"router role reaches the hub's networks", req("node-r", "10.60.0.10", 22, 6), true, "routers reach each other"},
		{"router role reaches the hub itself", req("node-r", "10.21.0.1", 0, 1), true, "routers reach each other"},
		{"hardware-bound node reaches port 80 in 10.60.0.0/24", req("node-a", "10.60.0.10", 80, 6), true, "hardware keys reach the target"},
		{"but not port 22", req("node-a", "10.60.0.10", 22, 6), false, ""},
		{"software key does not", req("node-b", "10.60.0.10", 80, 6), false, ""},
		{"self as principal", req("hub1", "10.21.0.2", 0, 1), false, ""},
	}
	for _, c := range cases {
		d := e.Evaluate(c.r)
		if d.Allow != c.want {
			t.Errorf("%s: allow=%v (policies %v errors %v)", c.name, d.Allow, d.Policies, d.Errors)
		}
		if c.pol != "" && (len(d.Policies) != 1 || d.Policies[0] != c.pol) {
			t.Errorf("%s: determining policies %v, want %s", c.name, d.Policies, c.pol)
		}
		if len(d.Errors) != 0 {
			t.Errorf("%s: evaluation errors %v", c.name, d.Errors)
		}
	}
	d := e.Evaluate(req("node-a", "192.168.178.10", 80, 6))
	if d.Session == nil || d.Session.Subject != "martin" || d.Owner == nil || d.Owner.ID != "node-r" {
		t.Fatalf("decision context: %+v", d)
	}
}

func TestSNIAndDNS(t *testing.T) {
	e := New(lab(
		registry.Policy{ID: "all", Name: "all", Cedar: `permit(principal, action, resource);`},
		registry.Policy{ID: "sni", Name: "no secret hosts", Cedar: `forbid(principal, action, resource) when { resource has sni && resource.sni like "secret.*" };`},
		registry.Policy{ID: "dns", Name: "no bad names", Cedar: `forbid(principal, action, resource) when { context has dns_name && context.dns_name == "evil.example" };`},
	))
	if len(e.Errors()) != 0 {
		t.Fatal(e.Errors())
	}
	r := req("node-a", "10.60.0.11", 443, 6)
	if !e.Evaluate(r).Allow {
		t.Fatal("TLS flow without SNI denied")
	}
	r.SNI = "secret.lab"
	if d := e.Evaluate(r); d.Allow || d.Policies[0] != "no secret hosts" {
		t.Fatalf("SNI forbid not applied: %+v", d)
	}
	r.SNI = "public.lab"
	if !e.Evaluate(r).Allow {
		t.Fatal("other SNI denied")
	}
	q := req("node-a", "10.60.0.53", 53, 17)
	q.DNSName = "evil.example"
	if e.Evaluate(q).Allow {
		t.Fatal("DNS forbid not applied")
	}
	q.DNSName = "good.example"
	if !e.Evaluate(q).Allow {
		t.Fatal("other DNS name denied")
	}
}

func TestPermitBySNIIsFlaggedForTheFlowTable(t *testing.T) {
	e := New(lab(
		registry.Policy{ID: "myip", Name: "myip", Cedar: `permit(principal, action, resource) when { resource has sni && resource.sni == "myip.wtf" };`},
	))
	r := req("node-a", "104.19.192.174", 443, 6)
	if d := e.Evaluate(r); d.Allow || !d.PermitBySNI {
		t.Fatalf("a SYN that a permit could allow by name: %+v", d)
	}
	r.SNI = "myip.wtf"
	if d := e.Evaluate(r); !d.Allow || d.PermitBySNI {
		t.Fatalf("with the name: %+v", d)
	}
	r.SNI = "other.example"
	if d := e.Evaluate(r); d.Allow || d.PermitBySNI {
		t.Fatalf("another name is a deny, nothing to wait for: %+v", d)
	}
	u := req("node-a", "104.19.192.174", 443, 17)
	if d := e.Evaluate(u); d.PermitBySNI {
		t.Fatal("UDP has no client hello to wait for")
	}
	f := New(lab(registry.Policy{ID: "x", Name: "x", Cedar: `forbid(principal, action, resource) when { resource has sni && resource.sni like "*.evil" };`}))
	if d := f.Evaluate(req("node-a", "104.19.192.174", 443, 6)); d.PermitBySNI {
		t.Fatal("a forbid by name does not make a deny worth waiting on")
	}
}

func TestBrokenPolicyIsSkipped(t *testing.T) {
	e := New(lab(
		registry.Policy{ID: "bad", Name: "bad", Cedar: `permit(principal, action, resource) when { this is not cedar };`},
		registry.Policy{ID: "good", Name: "good", Cedar: `permit(principal, action, resource) when { resource.port == 80 };`},
	))
	if len(e.Errors()) != 1 || e.Errors()[0].ID != "bad" || e.Policies() != 1 {
		t.Fatalf("errors %v policies %d", e.Errors(), e.Policies())
	}
	if !e.Evaluate(req("node-a", "10.60.0.10", 80, 6)).Allow || e.Evaluate(req("node-a", "10.60.0.10", 81, 6)).Allow {
		t.Fatal("remaining policy not applied")
	}
	if err := Validate(`permit(principal, action, resource) when { this is not cedar };`); err == nil {
		t.Fatal("Validate accepted garbage")
	}
	if err := Validate(""); err == nil {
		t.Fatal("Validate accepted an empty policy")
	}
	if err := Validate(`permit(principal, action, resource);` + "\n" + `forbid(principal, action, resource) when { resource.port == 25 };`); err != nil {
		t.Fatal(err)
	}
	if err := Validate(strings.Repeat("x", MaxPolicyBytes+1)); err == nil {
		t.Fatal("Validate accepted an oversized policy")
	}
}

func TestMissingAttributeIsAnErrorNotAPermit(t *testing.T) {
	e := New(lab(registry.Policy{ID: "p", Name: "needs sni", Cedar: `permit(principal, action, resource) when { resource.sni == "x" };`}))
	d := e.Evaluate(req("node-a", "10.60.0.10", 80, 6))
	if d.Allow || len(d.Errors) != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestOwner(t *testing.T) {
	s := lab()
	if n, ok := Owner(s, netip.MustParseAddr("192.168.178.10")); !ok || n.ID != "node-r" {
		t.Fatal("prefix owner")
	}
	if n, ok := Owner(s, netip.MustParseAddr("10.21.0.1")); !ok || n.ID != "hub1" {
		t.Fatal("self owner")
	}
	if _, ok := Owner(s, netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("unowned")
	}
}

// Tags name sets of nodes in policies: as the principal's group, as the
// owner of a destination, and as an attribute.
func TestTags(t *testing.T) {
	s := lab(
		registry.Policy{ID: "p-tag", Name: "laptops reach production", Cedar: `permit(principal in BoundGate::Tag::"laptop", action, resource in BoundGate::Tag::"production");`},
		registry.Policy{ID: "p-attr", Name: "not from lab machines", Cedar: `forbid(principal, action, resource) when { principal.tags.contains("lab") };`},
	)
	for i := range s.Peers {
		switch s.Peers[i].ID {
		case "node-a":
			s.Peers[i].Tags = []string{"laptop"}
		case "node-r":
			s.Peers[i].Tags = []string{"lab", "laptop"}
		}
	}
	s.Self.Tags = []string{"production"} // hub1 announces 10.60.0.0/24
	e := New(s)
	if len(e.Errors()) != 0 {
		t.Fatal(e.Errors())
	}
	if d := e.Evaluate(req("node-a", "10.60.0.10", 443, 6)); !d.Allow || len(d.Policies) != 1 || d.Policies[0] != "laptops reach production" {
		t.Fatalf("tagged laptop to a tagged node's network: %+v", d)
	}
	if d := e.Evaluate(req("node-a", "192.168.178.10", 443, 6)); d.Allow {
		t.Fatalf("a destination behind an untagged node was allowed: %+v", d)
	}
	if d := e.Evaluate(req("node-r", "10.60.0.10", 443, 6)); d.Allow || len(d.Policies) != 1 || d.Policies[0] != "not from lab machines" {
		t.Fatalf("forbid by tag attribute: %+v", d)
	}
}
