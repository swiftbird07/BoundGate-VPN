package transport_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// darkConn is a client socket whose network can go away: once dark, nothing
// reaches the client any more and nothing leaves it (a phone that left its
// Wi-Fi with the hub's connection still on it).
type darkConn struct {
	net.PacketConn
	dark atomic.Bool
}

func (c *darkConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.dark.Load() {
			return n, a, err
		}
	}
}

func (c *darkConn) WriteTo(b []byte, a net.Addr) (int, error) {
	if c.dark.Load() {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, a)
}

// floodHandler writes as fast as it can into every tunnel once told to,
// and reports how long the writes took and whether one failed.
type floodHandler struct {
	start chan struct{}
	done  chan error
	took  chan time.Duration
}

func (h *floodHandler) Accept(context.Context, transport.AuthenticatedPeer) (transport.TunnelConfig, int, error) {
	return transport.TunnelConfig{
		Assigned: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
		Routes:   []connectip.IPRoute{{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.255.255.255")}},
	}, http.StatusOK, nil
}

func (h *floodHandler) Serve(ctx context.Context, t *transport.Tunnel) {
	select {
	case <-h.start:
	case <-ctx.Done():
		return
	}
	began := time.Now()
	var err error
	for range 5000 {
		pkt := ipv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("100.96.0.2"), make([]byte, 1000))
		if _, err = t.WritePacket(pkt); err != nil {
			break
		}
	}
	h.took <- time.Since(began)
	h.done <- err
	<-ctx.Done()
}

func (h *floodHandler) Release(transport.AuthenticatedPeer, transport.TunnelConfig) {}

// A peer whose path went dark must not hold up the hub's writer: the hub
// writes into every tunnel from one TUN reader, and quic-go waits in
// SendDatagram once a connection that gets no acknowledgements has 32
// datagrams queued -- until its idle timeout.
func TestWritePacketDoesNotWaitForADeadPath(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	serverCert, roots := newServerCert(t)
	h := &floodHandler{start: make(chan struct{}), done: make(chan error, 1), took: make(chan time.Duration, 1)}
	srv, err := transport.NewServer(transport.ServerConfig{
		Addr:        "127.0.0.1:0",
		TLS:         transport.ServerTLSConfig(serverCert, lookup),
		Lookup:      lookup,
		Template:    "https://gateway.test/vpn",
		IdleTimeout: 10 * time.Second,
		KeepAlive:   time.Second,
	}, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); _ = srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-served })

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dc := &darkConn{PacketConn: udp}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	tun, err := transport.Dial(dctx, transport.ClientConfig{
		TLS:         transport.ClientTLSConfig(certA, roots, "gateway.test"),
		Template:    "https://gateway.test/vpn",
		IdleTimeout: 10 * time.Second,
		KeepAlive:   time.Second,
		PacketConn:  dc,
		Remote:      srv.LocalAddr(),
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()
	if _, err := tun.LocalPrefixes(dctx); err != nil {
		t.Fatal(err)
	}

	dc.dark.Store(true)
	close(h.start)
	select {
	case took := <-h.took:
		if err := <-h.done; err != nil {
			t.Fatalf("a write failed on a tunnel that is still open: %v", err)
		}
		if took > 2*time.Second {
			t.Fatalf("5000 writes took %v", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hub's writes waited for a peer whose path is dead")
	}
	// the client's writes do not wait either
	began := time.Now()
	for range 5000 {
		pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), make([]byte, 1000))
		if _, err := tun.WritePacket(pkt); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("the client's 5000 writes took %v", took)
	}
}
