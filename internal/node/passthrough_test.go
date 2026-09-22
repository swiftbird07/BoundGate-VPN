package node

import (
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// A peer without a user session reaches the login passthrough and nothing
// else; with a session, and for workloads, the policies decide as usual.
func TestLoginPassthrough(t *testing.T) {
	idp := netip.MustParsePrefix("136.243.123.200/32")
	n := &Node{cfg: Config{LoginPassthrough: []netip.Prefix{idp}}, holder: &registry.Holder{}}
	s := &session{n: n}
	snap := &registry.Snapshot{Peers: []registry.Node{
		{ID: "phone"},
		{ID: "server", Kind: registry.KindWorkload},
	}}
	n.holder.Store(snap)
	entry := func(peer transport.DeviceID, dst string) *flow.Entry {
		return &flow.Entry{Origin: flow.Origin{Principal: peer}, Target: netip.MustParseAddrPort(dst)}
	}

	if r, ok := s.loginPassthrough(entry("phone", "136.243.123.200:443")); !ok || !r.Allow {
		t.Fatalf("the way to the IdP before sign-in: %+v %v", r, ok)
	}
	if r, ok := s.loginPassthrough(entry("phone", "142.250.185.78:443")); !ok || r.Allow {
		t.Fatalf("anything else before sign-in must be denied: %+v %v", r, ok)
	}
	if _, ok := s.loginPassthrough(entry("server", "142.250.185.78:443")); ok {
		t.Fatal("a workload needs no session: the policies decide")
	}

	n.holder.Store(&registry.Snapshot{Peers: snap.Peers, Sessions: []registry.Session{
		{ID: "s1", NodeID: "phone", ExpiresAt: time.Now().Add(time.Hour)},
	}})
	if _, ok := s.loginPassthrough(entry("phone", "142.250.185.78:443")); ok {
		t.Fatal("with a session the policies decide")
	}

	n.cfg.LoginPassthrough = nil
	n.holder.Store(snap)
	if _, ok := s.loginPassthrough(entry("phone", "136.243.123.200:443")); ok {
		t.Fatal("without the option nothing changes (the hub refuses the tunnel before)")
	}
}

// DNS to a resolver the hub offers passes whatever the policies say, and
// only that: port 53, UDP or TCP, exactly the offered address.
func TestOfferedDNS(t *testing.T) {
	s := &session{n: &Node{cfg: Config{DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}}}
	for _, c := range []struct {
		dst   string
		proto uint8
		want  bool
	}{
		{"10.20.0.1:53", netparse.ProtoUDP, true},
		{"10.20.0.1:53", netparse.ProtoTCP, true},
		{"10.20.0.1:80", netparse.ProtoTCP, false},
		{"10.20.0.2:53", netparse.ProtoUDP, false},
		{"10.20.0.1:53", netparse.ProtoICMP, false},
	} {
		e := &flow.Entry{Origin: flow.Origin{Principal: "phone"}, Target: netip.MustParseAddrPort(c.dst), Proto: c.proto}
		if got := s.offeredDNS(e); got != c.want {
			t.Errorf("%s proto %d: %v, want %v", c.dst, c.proto, got, c.want)
		}
	}
}
