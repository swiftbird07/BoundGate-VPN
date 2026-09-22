package transport_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// relayHub is an echoHandler that also relays between the nodes it knows.
type relayHub struct {
	*echoHandler
	overlay map[transport.DeviceID]netip.Addr
}

func (h *relayHub) RelayListen(peer transport.AuthenticatedPeer, addr netip.Addr) int {
	if h.overlay[peer.DeviceID()] != addr {
		return http.StatusForbidden
	}
	return http.StatusOK
}

func (h *relayHub) RelayDial(peer transport.AuthenticatedPeer, target netip.Addr) (netip.Addr, int) {
	src, ok := h.overlay[peer.DeviceID()]
	if !ok || src == target {
		return netip.Addr{}, http.StatusForbidden
	}
	return src, http.StatusOK
}

func relayRemote(a netip.Addr) net.Addr { return transport.RelayAddr(a) }

func serve(t *testing.T, cfg transport.ServerConfig, h transport.Handler) *transport.Server {
	t.Helper()
	srv, err := transport.NewServer(cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return srv
}

func TestRelayCarriesTheTunnelHandshakeOfTwoNodes(t *testing.T) {
	certHub, spkiHub := newDevice(t, "hub")
	certA, spkiA := newDevice(t, "node-a")
	certB, spkiB := newDevice(t, "node-b")
	certC, spkiC := newDevice(t, "node-c") // approved, but never listens
	ipA, ipB, ipC := netip.MustParseAddr("10.21.0.5"), netip.MustParseAddr("10.21.0.6"), netip.MustParseAddr("10.21.0.7")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "a"}, spkiB: {ID: "b"}, spkiC: {ID: "c"}}}
	hubH := &relayHub{echoHandler: &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}, overlay: map[transport.DeviceID]netip.Addr{"a": ipA, "b": ipB, "c": ipC}}
	hub := serve(t, transport.ServerConfig{Addr: "127.0.0.1:0", TLS: transport.ServerTLSConfig(certHub, lookup), Lookup: lookup, Template: transport.HubTemplate, IdleTimeout: 5 * time.Second, KeepAlive: time.Second}, hubH)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dialHub := func(name string, c transport.ClientConfig) *transport.ClientTunnel {
		c.GatewayAddr, c.Template = hub.LocalAddr().String(), transport.HubTemplate
		tun, err := transport.Dial(ctx, c)
		if err != nil {
			t.Fatalf("%s to hub: %v", name, err)
		}
		t.Cleanup(func() { _ = tun.Close() })
		return tun
	}
	a := dialHub("a", transport.ClientConfig{TLS: transport.ClientTLSConfigPinned(certA, spkiHub)})
	b := dialHub("b", transport.ClientConfig{TLS: transport.ClientTLSConfigPinned(certB, spkiHub)})

	// nobody listens for b yet
	var re *transport.RelayError
	if _, err := a.RelayDial(ctx, ipA, ipB); !errors.As(err, &re) || re.Status != http.StatusNotFound {
		t.Fatalf("dial without a listener: %v", err)
	}
	// b may not listen for someone else's address
	if _, err := b.RelayListen(ctx, ipC); !errors.As(err, &re) || re.Status != http.StatusForbidden {
		t.Fatalf("listen for a foreign address: %v", err)
	}

	// b listens and serves tunnels to approved nodes on the relay stream
	pcB, err := b.RelayListen(ctx, ipB)
	if err != nil {
		t.Fatal(err)
	}
	onlyA := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "a"}}}
	hB := &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}
	serve(t, transport.ServerConfig{PacketConn: pcB, Relayed: true, TLS: transport.ServerTLSConfig(certB, onlyA), Lookup: onlyA, Template: transport.HubTemplate, IdleTimeout: 5 * time.Second, KeepAlive: time.Second}, hB)

	// a reaches b: the same handshake as to a hub, pinned to b's key
	pcA, err := a.RelayDial(ctx, ipA, ipB)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := transport.Dial(ctx, transport.ClientConfig{PacketConn: pcA, Remote: relayRemote(ipB), TLS: transport.ClientTLSConfigPinned(certA, spkiB), Template: transport.HubTemplate, IdleTimeout: 5 * time.Second, KeepAlive: time.Second})
	if err != nil {
		t.Fatalf("a to b through the relay: %v", err)
	}
	defer ab.Close()
	if ab.Transport() != "relay" {
		t.Fatalf("transport %q", ab.Transport())
	}
	select {
	case peer := <-hB.accepted:
		if peer.DeviceID() != "a" || peer.SPKI() != spkiA || peer.SourceIP() != ipA {
			t.Fatalf("b authenticated %v", peer)
		}
	case <-ctx.Done():
		t.Fatal("b never accepted")
	}
	pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("through the hub, not readable by it"))
	if _, err := ab.WritePacket(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := ab.ReadPacket(buf)
	if err != nil || string(buf[20:n]) != "through the hub, not readable by it" {
		t.Fatalf("echo: %v %q", err, buf[:n])
	}
	if st := hub.RelayStats(); st.Listeners != 1 || st.Dialers != 1 || st.Packets == 0 {
		t.Fatalf("relay stats %+v", st)
	}

	// a node that b does not know fails b's handshake, relay or not
	c := dialHub("c", transport.ClientConfig{TLS: transport.ClientTLSConfigPinned(certC, spkiHub)})
	pcC, err := c.RelayDial(ctx, ipC, ipB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Dial(ctx, transport.ClientConfig{PacketConn: pcC, Remote: relayRemote(ipB), TLS: transport.ClientTLSConfigPinned(certC, spkiB), Template: transport.HubTemplate, HandshakeTimeout: 2 * time.Second}); err == nil {
		t.Fatal("b accepted a node it does not know")
	}
	// and a relay cannot stand in for b: the dialer pins b's key
	pcA2, err := a.RelayDial(ctx, ipA, ipB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Dial(ctx, transport.ClientConfig{PacketConn: pcA2, Remote: relayRemote(ipB), TLS: transport.ClientTLSConfigPinned(certA, spkiC), Template: transport.HubTemplate, HandshakeTimeout: 2 * time.Second}); err == nil {
		t.Fatal("handshake succeeded against the wrong key")
	}

	// the hub drops b (revoked, user session over): b's listener is gone, and
	// a's tunnel to b ends at once instead of idling out; a itself stays
	if hub.CloseDevice("b", transport.ErrCodeRevoked, "test") == 0 {
		t.Fatal("hub had no tunnel of b")
	}
	select {
	case <-ab.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the relayed tunnel outlived the listener it led to")
	}
	if a.Err() != nil {
		t.Fatalf("a's own hub tunnel ended: %v", a.Err())
	}
	if _, err := a.RelayDial(ctx, ipA, ipB); !errors.As(err, &re) || re.Status != http.StatusNotFound {
		t.Fatalf("dial after the listener left: %v", err)
	}
}

func TestRelayNeedsAHubThatRelays(t *testing.T) {
	certA, spkiA := newDevice(t, "node-a")
	env := startServer(t, &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "a"}}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tun, err := env.dial(t, certA)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	var re *transport.RelayError
	if _, err := tun.RelayListen(ctx, netip.MustParseAddr("10.21.0.5")); !errors.As(err, &re) || re.Status != http.StatusNotImplemented {
		t.Fatalf("hub without a relay: %v", err)
	}
	tcp, err := env.dialTCP(t, certA)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if _, err := tcp.RelayListen(ctx, netip.MustParseAddr("10.21.0.5")); !errors.As(err, &re) || re.Status != http.StatusNotImplemented {
		t.Fatalf("tcp link against a hub without a relay: %v", err)
	}
}

// A node whose network blocks UDP reaches its peers all the same: its relay
// streams are second TLS connections to the same hub, upgraded to
// connect-udp, carrying the same datagrams as capsules.
func TestRelayOverTheTCPFallback(t *testing.T) {
	certHub, spkiHub := newDevice(t, "hub")
	certA, spkiA := newDevice(t, "node-a")
	certB, spkiB := newDevice(t, "node-b")
	ipA, ipB := netip.MustParseAddr("10.21.0.5"), netip.MustParseAddr("10.21.0.6")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "a"}, spkiB: {ID: "b"}}}
	hubH := &relayHub{echoHandler: &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}, overlay: map[transport.DeviceID]netip.Addr{"a": ipA, "b": ipB}}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := serve(t, transport.ServerConfig{Addr: "127.0.0.1:0", TLS: transport.ServerTLSConfig(certHub, lookup), Lookup: lookup, Template: transport.HubTemplate,
		IdleTimeout: 5 * time.Second, KeepAlive: time.Second, TCPListener: tcpLn}, hubH)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dialTCPHub := func(name string, cert tls.Certificate) *transport.ClientTunnel {
		tun, err := transport.DialTCP(ctx, transport.ClientConfig{GatewayAddr: tcpLn.Addr().String(), TLS: transport.ClientTLSConfigPinned(cert, spkiHub),
			Template: transport.HubTemplate, IdleTimeout: 5 * time.Second, KeepAlive: time.Second})
		if err != nil {
			t.Fatalf("%s to hub over TCP: %v", name, err)
		}
		t.Cleanup(func() { _ = tun.Close() })
		if tun.Transport() != "tcp" {
			t.Fatalf("%s: transport %q", name, tun.Transport())
		}
		return tun
	}
	a, b := dialTCPHub("a", certA), dialTCPHub("b", certB)

	pcB, err := b.RelayListen(ctx, ipB)
	if err != nil {
		t.Fatalf("listen over TCP: %v", err)
	}
	onlyA := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "a"}}}
	hB := &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}
	serve(t, transport.ServerConfig{PacketConn: pcB, Relayed: true, TLS: transport.ServerTLSConfig(certB, onlyA), Lookup: onlyA, Template: transport.HubTemplate,
		IdleTimeout: 5 * time.Second, KeepAlive: time.Second}, hB)

	pcA, err := a.RelayDial(ctx, ipA, ipB)
	if err != nil {
		t.Fatalf("dial over TCP: %v", err)
	}
	ab, err := transport.Dial(ctx, transport.ClientConfig{PacketConn: pcA, Remote: relayRemote(ipB), TLS: transport.ClientTLSConfigPinned(certA, spkiB),
		Template: transport.HubTemplate, IdleTimeout: 5 * time.Second, KeepAlive: time.Second})
	if err != nil {
		t.Fatalf("a to b through the relay on TCP: %v", err)
	}
	defer ab.Close()
	select {
	case peer := <-hB.accepted:
		if peer.DeviceID() != "a" || peer.SPKI() != spkiA || peer.SourceIP() != ipA {
			t.Fatalf("b authenticated %v", peer)
		}
	case <-ctx.Done():
		t.Fatal("b never accepted")
	}
	pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("relayed while UDP is blocked"))
	if _, err := ab.WritePacket(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := ab.ReadPacket(buf)
	if err != nil || string(buf[20:n]) != "relayed while UDP is blocked" {
		t.Fatalf("echo: %v %q", err, buf[:n])
	}
	if st := hub.RelayStats(); st.Listeners != 1 || st.Dialers != 1 || st.Packets == 0 {
		t.Fatalf("relay stats %+v", st)
	}
	// the hub drops b: its listener goes, and the relayed tunnel ends with it
	if hub.CloseDevice("b", transport.ErrCodeRevoked, "test") == 0 {
		t.Fatal("hub had no tunnel of b")
	}
	select {
	case <-ab.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the relayed tunnel outlived the listener it led to")
	}
}
