package acl

import (
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// A dynamic access list is one list for a destination however the node sees
// it: the DNS question, the name it resolved to an address, the TLS server
// name, and addresses with ports written into the list by hand.
func TestDynamicListMatchesNameAddressAndWhatWasResolved(t *testing.T) {
	snap := lab(registry.Policy{ID: "ok", Name: "work", Cedar: `permit(principal, action, resource in BoundGate::List::"work");`})
	snap.Lists = []registry.List{{Name: "work", Kind: "dynamic", Entries: []string{
		"*.github.com", "myip.wtf", "10.60.0.10", "10.60.0.64/26", "192.168.178.20-192.168.178.29", "10.60.0.11:443", "10.60.0.12:8000-8100",
	}}}
	e := New(snap)
	if len(e.Errors()) != 0 {
		t.Fatal(e.Errors())
	}

	// the query for a name in the list, to a resolver that is not in it
	q := req("node-a", "10.60.0.53", 53, 17)
	q.DNSName = "api.github.com"
	if d := e.Evaluate(q); !d.Allow {
		t.Fatalf("the question is what the list holds: %+v", d)
	}
	q.DNSName = "tracker.example"
	if d := e.Evaluate(q); d.Allow {
		t.Fatalf("another name is not in the list: %+v", d)
	}

	// the connection afterwards: plain HTTP to the address the answer named
	plain := req("node-a", "140.82.121.4", 80, 6)
	if d := e.Evaluate(plain); d.Allow {
		t.Fatalf("an address nobody resolved is not in the list: %+v", d)
	}
	plain.Resolved = []string{"api.github.com"}
	if d := e.Evaluate(plain); !d.Allow {
		t.Fatalf("the address this node resolved the name to: %+v", d)
	}
	plain.Resolved = []string{"tracker.example"}
	if d := e.Evaluate(plain); d.Allow {
		t.Fatalf("resolved, but not a name of this list: %+v", d)
	}

	// TLS without a resolution the node saw: the server name still decides
	tls := req("node-a", "104.19.192.174", 443, 6)
	if d := e.Evaluate(tls); d.Allow || !d.PermitBySNI {
		t.Fatalf("no name yet, but worth waiting for the hello: %+v", d)
	}
	tls.SNI = "myip.wtf"
	if d := e.Evaluate(tls); !d.Allow {
		t.Fatalf("server name in the list: %+v", d)
	}

	// the addresses written into the list, with and without a port
	for _, c := range []struct {
		ip    string
		port  uint16
		allow bool
	}{
		{"10.60.0.10", 80, true},
		{"10.60.0.10", 9999, true},
		{"10.60.0.9", 80, false},
		{"10.60.0.64", 80, true},
		{"10.60.0.127", 80, true},
		{"10.60.0.128", 80, false},
		{"192.168.178.25", 80, true},
		{"192.168.178.30", 80, false},
		{"10.60.0.11", 443, true},
		{"10.60.0.11", 80, false},
		{"10.60.0.12", 8080, true},
		{"10.60.0.12", 8101, false},
	} {
		if d := e.Evaluate(req("node-a", c.ip, c.port, 6)); d.Allow != c.allow {
			t.Fatalf("%s:%d allow=%v, want %v", c.ip, c.port, d.Allow, c.allow)
		}
	}
}

// Only a dynamic list makes the node remember addresses, and only for the
// names it holds.
func TestEngineLearnsOnlyWhatADynamicListHolds(t *testing.T) {
	snap := lab()
	snap.Lists = []registry.List{{Name: "names", Kind: "dns", Entries: []string{"api.github.com"}}}
	if e := New(snap); e.LearnsNames() || e.Learns("api.github.com") {
		t.Fatal("a dns list decides the query, it teaches nothing")
	}
	snap.Lists[0].Kind = "dynamic"
	e := New(snap)
	if !e.LearnsNames() || !e.Learns("api.github.com") || e.Learns("tracker.example") {
		t.Fatalf("learns: %v %v %v", e.LearnsNames(), e.Learns("api.github.com"), e.Learns("tracker.example"))
	}
	// a wildcard entry teaches the node about every name below it
	snap.Lists[0].Entries = []string{"*.github.com"}
	e = New(snap)
	if !e.Learns("api.github.com") || !e.Learns("raw.contents.github.com") || e.Learns("github.com") {
		t.Fatal("*.github.com covers what is below it, not the name itself")
	}
}

// A server name is whatever the client writes into its ClientHello. It may
// stand in for a resolution only on the way to the internet: inside the
// overlay, in a network a node announces or in a private range it would
// open every TLS service to whoever types a permitted name.
func TestDynamicListServerNameOnlyForPublicAddresses(t *testing.T) {
	snap := lab(registry.Policy{ID: "ok", Name: "work", Cedar: `permit(principal, action, resource in BoundGate::List::"work");`})
	snap.Lists = []registry.List{{Name: "work", Kind: "dynamic", Entries: []string{"myip.wtf"}}}
	e := New(snap)
	for _, c := range []struct {
		dst   string
		allow bool
	}{
		{"104.19.192.174", true},  // the internet, through an exit node
		{"10.60.0.10", false},     // the hub's own network
		{"192.168.178.20", false}, // a router's network
		{"10.21.0.4", false},      // another node
		{"172.16.5.5", false},     // a private range nobody announces
		{"100.64.1.1", false},     // shared address space
	} {
		r := req("node-a", c.dst, 443, 6)
		if d := e.Evaluate(r); d.Allow || d.PermitBySNI != c.allow {
			t.Fatalf("%s before the hello: allow=%v probe=%v", c.dst, d.Allow, d.PermitBySNI)
		}
		r.SNI = "myip.wtf"
		if d := e.Evaluate(r); d.Allow != c.allow {
			t.Fatalf("%s with a permitted server name: allow=%v, want %v", c.dst, d.Allow, c.allow)
		}
		// what the node saw this device resolve still counts everywhere
		r.Resolved = []string{"myip.wtf"}
		if d := e.Evaluate(r); !d.Allow {
			t.Fatalf("%s resolved by this device: %+v", c.dst, d)
		}
	}

	// an sni list is the admin's explicit choice and keeps its meaning
	snap.Lists = append(snap.Lists, registry.List{Name: "names", Kind: "sni", Entries: []string{"git.lab"}})
	snap.Policies = append(snap.Policies, registry.Policy{ID: "sni", Name: "git", Cedar: `permit(principal, action, resource in BoundGate::List::"names");`})
	e = New(snap)
	r := req("node-a", "10.60.0.10", 443, 6)
	r.SNI = "git.lab"
	if !e.Evaluate(r).Allow {
		t.Fatal("an sni list matches the server name wherever it points")
	}
}

// Only a permit that reads the server name makes a denied SYN wait for the
// ClientHello; an entity or a string that merely contains "sni" does not.
func TestPermitsBySNIReadsTheAttributeNotTheLetters(t *testing.T) {
	for cedarText, want := range map[string]bool{
		`permit(principal, action, resource) when { resource.sni == "a.example" };`:             true,
		`permit(principal, action, resource) when { context has sni && context.sni like "*" };`: true,
		`permit(principal == BoundGate::Node::"snipe", action, resource);`:                      false,
		`permit(principal, action, resource) when { resource.dns_name == "snide.example" };`:    false,
	} {
		e := New(lab(registry.Policy{ID: "p", Name: "p", Cedar: cedarText}))
		if len(e.Errors()) != 0 {
			t.Fatal(e.Errors())
		}
		if got := e.Evaluate(req("node-b", "10.60.0.10", 443, 6)).PermitBySNI; got != want {
			t.Fatalf("%s: probe=%v, want %v", cedarText, got, want)
		}
	}
}
