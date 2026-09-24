package transport_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// gatedConn is a UDP socket for a server whose peers can be cut off: packets
// from and to the addresses seen so far are dropped, as after a NAT binding
// expired. dropAll swallows everything the server sends (a host that
// vanished without a word).
type gatedConn struct {
	net.PacketConn
	mu      sync.Mutex
	seen    map[string]bool
	cut     map[string]bool
	dropAll bool
}

// cutOff drops every peer seen so far.
func (g *gatedConn) cutOff() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cut = g.seen
	g.seen = nil
}

func (g *gatedConn) blocked(addr net.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]bool)
	}
	g.seen[addr.String()] = true
	return g.dropAll || g.cut[addr.String()]
}

func (g *gatedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := g.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if !g.blocked(addr) {
			return n, addr, nil
		}
	}
}

func (g *gatedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if g.blocked(addr) {
		return len(b), nil
	}
	return g.PacketConn.WriteTo(b, addr)
}

type gatedEnv struct {
	srv   *transport.Server
	h     *echoHandler
	roots *x509.CertPool
	stop  context.CancelFunc
}

func serveOn(t *testing.T, pc net.PacketConn, lookup *staticLookup, key *quic.StatelessResetKey) *gatedEnv {
	t.Helper()
	serverCert, roots := newServerCert(t)
	h := &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}
	srv, err := transport.NewServer(transport.ServerConfig{
		PacketConn: pc, TLS: transport.ServerTLSConfig(serverCert, lookup), Lookup: lookup,
		Template: "https://gateway.test/vpn", IdleTimeout: 30 * time.Second, KeepAlive: -1,
		StatelessResetKey: key,
	}, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()
	return &gatedEnv{srv: srv, h: h, roots: roots, stop: func() { cancel(); <-done }}
}

func (e *gatedEnv) dial(t *testing.T, cert tls.Certificate, addr string) *transport.ClientTunnel {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tun, err := transport.Dial(ctx, transport.ClientConfig{
		GatewayAddr: addr, TLS: transport.ClientTLSConfig(cert, e.roots, "gateway.test"),
		Template: "https://gateway.test/vpn", IdleTimeout: 30 * time.Second, KeepAlive: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tun
}

func echo(t *testing.T, tun *transport.ClientTunnel, within time.Duration) error {
	t.Helper()
	pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("hello"))
	if _, err := tun.WritePacket(pkt); err != nil {
		return err
	}
	buf := make([]byte, 2000)
	got := make(chan error, 1)
	go func() { _, err := tun.ReadPacket(buf); got <- err }()
	select {
	case err := <-got:
		return err
	case <-time.After(within):
		return errors.New("no echo")
	}
}

// After a network change the tunnel moves to a new socket: the hub answers
// on the new address and the tunnel goes on, same address, same routes.
func TestMigrateMovesTheTunnelToANewSocket(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	env := startServer(t, lookup)
	tun, err := env.dial(t, certA)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if err := echo(t, tun, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tun.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for range 3 {
		if err := echo(t, tun, 5*time.Second); err != nil {
			t.Fatalf("after the migration: %v", err)
		}
	}
	// a second move works as well (Wi-Fi -> cellular -> Wi-Fi)
	if err := tun.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := echo(t, tun, 5*time.Second); err != nil {
		t.Fatalf("after the second migration: %v", err)
	}

	tcp, err := env.dialTCP(t, certA)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if err := tcp.Migrate(ctx); !errors.Is(err, transport.ErrNoMigration) {
		t.Fatalf("tcp migrate: %v, want ErrNoMigration", err)
	}
}

// A tunnel whose NAT binding vanished swallows packets without QUIC noticing
// before its idle timeout. The client notices on its own: after silentFor of
// sending without an answer it probes from a new socket, the hub answers
// there, and the tunnel continues.
func TestStalledTunnelRecoversThroughANewSocket(t *testing.T) {
	defer transport.SetLiveness(500*time.Millisecond, 3)()
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gate := &gatedConn{PacketConn: pc}
	env := serveOn(t, gate, lookup, nil)
	defer env.stop()
	tun := env.dial(t, certA, pc.LocalAddr().String())
	defer tun.Close()
	if err := echo(t, tun, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	gate.cutOff()
	if err := echo(t, tun, time.Second); err == nil {
		t.Fatal("the cut-off tunnel still echoes")
	}
	// keep sending, as an application with a stalled connection does
	pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("hello"))
	deadline := time.Now().Add(15 * time.Second)
	buf := make([]byte, 2000)
	answered := make(chan struct{})
	go func() {
		for {
			if _, err := tun.ReadPacket(buf); err != nil {
				return
			}
			select {
			case <-answered:
			default:
				close(answered)
			}
		}
	}()
	for time.Now().Before(deadline) {
		if _, err := tun.WritePacket(pkt); err != nil {
			t.Fatalf("write: %v (%v)", err, tun.Err())
		}
		select {
		case <-answered:
			return
		case <-tun.Done():
			t.Fatalf("the tunnel ended instead of moving: %v", tun.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("the stalled tunnel did not recover")
}

// A hub that restarted does not know the tunnels of before. With a stateless
// reset key it tells a client so on the first packet; the client's tunnel
// ends at once (and is dialed again) instead of at the idle timeout.
func TestRestartedHubSendsStatelessReset(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	var key quic.StatelessResetKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	gate := &gatedConn{PacketConn: pc}
	env := serveOn(t, gate, lookup, &key)
	tun := env.dial(t, certA, addr)
	defer tun.Close()
	if err := echo(t, tun, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// the hub goes down without a word (its CONNECTION_CLOSE never leaves)
	gate.mu.Lock()
	gate.dropAll = true
	gate.mu.Unlock()
	env.stop()
	pc2, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	env2 := serveOn(t, pc2, lookup, &key)
	defer env2.stop()

	pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("hello"))
	_, _ = tun.WritePacket(pkt)
	select {
	case <-tun.Done():
		var reset *quic.StatelessResetError
		if !errors.As(tun.Err(), &reset) {
			t.Fatalf("tunnel ended with %v, want a stateless reset", tun.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel to the restarted hub did not end")
	}

	// the same tunnel dials fine against the new hub
	tun2 := env2.dial(t, certA, addr)
	defer tun2.Close()
	if err := echo(t, tun2, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}
