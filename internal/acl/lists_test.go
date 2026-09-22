package acl

import (
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

func TestListsAreParentsOfTheDestination(t *testing.T) {
	snap := lab(
		registry.Policy{ID: "ok", Name: "allowed sites", Cedar: `permit(principal, action, resource in BoundGate::List::"allowed-sites");`},
		registry.Policy{ID: "lan", Name: "lan", Cedar: `permit(principal, action, resource in BoundGate::Network::"10.60.0.0/24") unless { resource in BoundGate::List::"blocked-hosts" };`},
		registry.Policy{ID: "dns", Name: "no ads", Cedar: `forbid(principal, action, resource in BoundGate::List::"ad-domains");`},
		registry.Policy{ID: "any", Name: "dns ok", Cedar: `permit(principal, action, resource) when { context has dns_name };`},
	)
	snap.Lists = []registry.List{
		{Name: "allowed-sites", Kind: "sni", Entries: []string{"myip.wtf", "*.github.com"}},
		{Name: "blocked-hosts", Kind: "ip", Entries: []string{"10.60.0.11/32", "10.60.0.128/25"}},
		{Name: "ad-domains", Kind: "dns", Entries: []string{"*.ads.example", "tracker.example"}},
	}
	e := New(snap)
	if len(e.Errors()) != 0 {
		t.Fatal(e.Errors())
	}
	tls := req("node-a", "104.19.192.174", 443, 6)
	if d := e.Evaluate(tls); d.Allow || !d.PermitBySNI {
		t.Fatalf("no name yet: denied, but worth waiting for the hello: %+v", d)
	}
	for name, want := range map[string]bool{"myip.wtf": true, "MyIP.wtf.": true, "api.github.com": true, "github.com": false, "evilgithub.com": false, "other.example": false} {
		tls.SNI = name
		if d := e.Evaluate(tls); d.Allow != want {
			t.Fatalf("sni %q: allow=%v, want %v (%+v)", name, d.Allow, want, d)
		}
	}
	if d := e.Evaluate(req("node-a", "10.60.0.10", 80, 6)); !d.Allow {
		t.Fatalf("lan host not in the block list: %+v", d)
	}
	for _, ip := range []string{"10.60.0.11", "10.60.0.200"} {
		if d := e.Evaluate(req("node-a", ip, 80, 6)); d.Allow {
			t.Fatalf("%s is in blocked-hosts: %+v", ip, d)
		}
	}
	q := req("node-a", "10.60.0.53", 53, 17)
	for name, want := range map[string]bool{"good.example": true, "tracker.example": false, "x.ads.example": false, "ads.example": true} {
		q.DNSName = name
		if d := e.Evaluate(q); d.Allow != want {
			t.Fatalf("dns %q: allow=%v, want %v", name, d.Allow, want)
		}
	}
}

func TestPermitByListOfNamesWaitsForTheHello(t *testing.T) {
	snap := lab(registry.Policy{ID: "ok", Name: "ok", Cedar: `permit(principal, action, resource in BoundGate::List::"sites");`})
	snap.Lists = []registry.List{{Name: "sites", Kind: "ip", Entries: []string{"10.60.0.0/24"}}}
	if d := New(snap).Evaluate(req("node-a", "104.19.192.174", 443, 6)); d.PermitBySNI {
		t.Fatal("an ip list has nothing to do with the hello")
	}
	snap.Lists[0].Kind = "sni"
	if d := New(snap).Evaluate(req("node-a", "104.19.192.174", 443, 6)); !d.PermitBySNI {
		t.Fatal("a permit by a list of server names waits for the hello")
	}
}
