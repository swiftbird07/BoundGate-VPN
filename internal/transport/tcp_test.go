package transport_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// The TCP fallback carries the same tunnel: assigned address, advertised
// routes, packets both ways, the peer's real address, the transport label.
func TestTCPFallbackEcho(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	env := startServer(t, lookup)

	tun, err := env.dialTCP(t, certA)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer tun.Close()
	if tun.Transport() != "tcp" {
		t.Fatalf("transport %q", tun.Transport())
	}
	select {
	case peer := <-env.h.accepted:
		if peer.DeviceID() != "dev-a" || !peer.SourceIP().IsLoopback() {
			t.Fatalf("peer %v", peer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	checkDNS(t, tun.DNS())
	prefixes, err := tun.LocalPrefixes(ctx)
	if err != nil || len(prefixes) != 1 || prefixes[0] != netip.MustParsePrefix("100.96.0.2/32") {
		t.Fatalf("prefixes %v, %v", prefixes, err)
	}
	routes, err := tun.Routes(ctx)
	if err != nil || len(routes) != 1 || routes[0].StartIP != netip.MustParseAddr("10.0.0.0") || routes[0].EndIP != netip.MustParseAddr("10.255.255.255") {
		t.Fatalf("routes %v, %v", routes, err)
	}
	for i := 0; i < 50; i++ { // more than the queue holds in one go is not needed; several round trips are
		pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("hello"))
		if _, err := tun.WritePacket(pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2000)
		n, err := tun.ReadPacket(buf)
		if err != nil {
			t.Fatal(err)
		}
		got := buf[:n]
		if netip.AddrFrom4([4]byte(got[12:16])) != netip.MustParseAddr("10.0.0.1") ||
			netip.AddrFrom4([4]byte(got[16:20])) != netip.MustParseAddr("100.96.0.2") ||
			string(got[20:]) != "hello" || got[8] != 62 { // TTL 64 decremented on each hop
			t.Fatalf("unexpected echo %x", got)
		}
	}
	// keep-alives (200 ms) crossed the idle timeout of neither side
	time.Sleep(600 * time.Millisecond)
	if tun.Err() != nil {
		t.Fatalf("tunnel ended: %v", tun.Err())
	}
}

// Revocation and shutdown reach a TCP client with the same codes as QUIC.
func TestTCPFallbackCloseCodes(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	env := startServer(t, lookup)
	tun, err := env.dialTCP(t, certA)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	<-env.h.accepted
	// Accept runs before the server tracks the tunnel: wait for that
	deadline := time.Now().Add(5 * time.Second)
	for len(env.srv.ActiveDevices()) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("active %v", env.srv.ActiveDevices())
		}
		time.Sleep(5 * time.Millisecond)
	}
	env.lookup.remove(spkiA)
	if n := env.srv.CloseDevice("dev-a", transport.ErrCodeRevoked, "unenrolled"); n != 1 {
		t.Fatalf("closed %d", n)
	}
	select {
	case <-tun.Done():
		code, ok := transport.CloseCode(tun.Err())
		if !ok || code != transport.ErrCodeRevoked {
			t.Fatalf("close reason %v", tun.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked tunnel still open")
	}
	if _, err := env.dialTCP(t, certA); err == nil {
		t.Fatal("revoked device reconnected over tcp")
	}
	// an unknown device never gets past the handshake
	certX, _ := newDevice(t, "device-x")
	if _, err := env.dialTCP(t, certX); err == nil {
		t.Fatal("unknown device got a tcp tunnel")
	}
}

// A refusal by the handler is an HTTP status on TCP too (403 = login).
func TestTCPFallbackRefusal(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	env := startServer(t, lookup)
	env.h.refuse = 403
	_, err := env.dialTCP(t, certA)
	var de *transport.DialError
	if !errors.As(err, &de) || de.Status != 403 {
		t.Fatalf("want DialError 403, got %v", err)
	}
}
