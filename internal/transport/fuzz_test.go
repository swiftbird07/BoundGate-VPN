package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// capsule frames one capsule the way writeCapsule does.
func capsule(typ uint64, payload []byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

func assignPayload(ps ...netip.Prefix) []byte {
	var b []byte
	for _, p := range ps {
		b = quicvarint.Append(b, 0)
		b = appendPrefix(b, p)
	}
	return b
}

func routesPayload(rs ...connectip.IPRoute) []byte {
	var b []byte
	for _, r := range rs {
		if r.StartIP.Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, r.StartIP.AsSlice()...)
		b = append(b, r.EndIP.AsSlice()...)
		b = append(b, r.IPProtocol)
	}
	return b
}

func ipv4Packet(ttl byte, payload int) []byte {
	b := make([]byte, 20+payload)
	b[0], b[8], b[9] = 0x45, ttl, 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:], []byte{100, 96, 0, 2, 10, 0, 0, 1})
	return b
}

func FuzzParseAssign(f *testing.F) {
	f.Add(assignPayload(netip.MustParsePrefix("100.96.0.2/32"), netip.MustParsePrefix("10.60.0.0/24")))
	f.Add(assignPayload(netip.MustParsePrefix("fd00::/64")))
	f.Add([]byte{0x40, 0x07, 4, 1, 2, 3, 4, 33})
	f.Fuzz(func(t *testing.T, b []byte) {
		ps, err := parseAssign(b)
		if err != nil {
			return
		}
		for _, p := range ps {
			if !p.IsValid() || p.Masked() != p {
				t.Fatalf("accepted %s", p)
			}
		}
		again, err := parseAssign(assignPayload(ps...))
		if err != nil || !slices.Equal(again, ps) {
			t.Fatalf("%v does not survive a round trip: %v %v", ps, again, err)
		}
	})
}

func FuzzParseRoutes(f *testing.F) {
	f.Add(routesPayload(
		connectip.IPRoute{StartIP: netip.MustParseAddr("100.96.0.0"), EndIP: netip.MustParseAddr("100.127.255.255")},
		connectip.IPRoute{StartIP: netip.MustParseAddr("fd00::"), EndIP: netip.MustParseAddr("fd00::ffff"), IPProtocol: 6},
	))
	f.Add([]byte{4, 10, 0, 0, 9, 10, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, err := parseRoutes(b)
		if err != nil {
			return
		}
		for _, r := range rs {
			if r.StartIP.BitLen() != r.EndIP.BitLen() || r.EndIP.Less(r.StartIP) {
				t.Fatalf("accepted %v", r)
			}
		}
		if !bytes.Equal(routesPayload(rs...), b) {
			t.Fatalf("%v does not encode to its input", rs)
		}
	})
}

// A capsule stream from the peer (TCP fallback) never panics the reader
// goroutine, which has no recover, and yields only IP packets that fit.
func FuzzCapsuleLinkRead(f *testing.F) {
	pkt := ipv4Packet(64, 12)
	f.Add(slices.Concat(
		capsule(capsuleAssign, assignPayload(netip.MustParsePrefix("100.96.0.2/32"))),
		capsule(capsuleRoutes, routesPayload(connectip.IPRoute{StartIP: netip.MustParseAddr("100.96.0.0"), EndIP: netip.MustParseAddr("100.96.255.255")})),
		capsule(capsuleDatagram, append([]byte{0}, pkt...)),
		capsule(capsuleDatagram, append([]byte{1}, pkt...)),
		capsule(capsuleDatagram, []byte{0}),
		capsule(capsuleBGPing, nil),
		capsule(0x1234, []byte("unknown")),
		capsule(capsuleBGClose, append(quicvarint.Append(nil, 7), "bye"...)),
	))
	f.Add(capsule(capsuleDatagram, nil))
	f.Add([]byte{0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, stream []byte) {
		c, s := net.Pipe()
		l := newCapsuleLink(s, nil, 5*time.Second, 0, false)
		go func() {
			_, _ = c.Write(stream)
			_ = c.Close()
		}()
		buf := make([]byte, 65535)
		for i := 0; ; i++ {
			n, err := l.ReadPacket(buf)
			if err != nil {
				break
			}
			if n <= 0 || n > len(buf) || i > len(stream) {
				t.Fatalf("packet %d of %d bytes", i, n)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = l.LocalPrefixes(ctx)
		_, _ = l.Routes(ctx)
		_ = l.Err()
		_ = l.Close(0, "done")
	})
}

// What one end writes the other end reads, TTL decremented, on both
// transports' terms: nothing is lost or reordered, and the writer's buffer
// is not kept.
func FuzzCapsuleRoundTrip(f *testing.F) {
	f.Add(ipv4Packet(64, 100), uint8(2))
	f.Add(ipv4Packet(1, 0), uint8(1))
	f.Add(append([]byte{0x60, 0, 0, 0, 0, 8, 17, 2}, make([]byte, 40)...), uint8(3))
	f.Fuzz(func(t *testing.T, pkt []byte, copies uint8) {
		if len(pkt) > 65535 {
			return
		}
		a, b := net.Pipe()
		la := newCapsuleLink(a, nil, 5*time.Second, 0, true)
		lb := newCapsuleLink(b, nil, 5*time.Second, 0, false)
		defer la.Close(0, "done")
		defer lb.Close(0, "done")
		buf := make([]byte, 65535)
		for i := 0; i < int(copies%4); i++ {
			w := append([]byte(nil), pkt...)
			sent := false
			switch {
			case len(w) >= 20 && w[0]>>4 == 4 && w[8] > 1, len(w) >= 40 && w[0]>>4 == 6 && w[7] > 1:
				sent = true
			}
			if _, err := la.WritePacket(w); err != nil {
				t.Fatal(err)
			}
			if !sent {
				if !bytes.Equal(w, pkt) {
					t.Fatal("a dropped packet was modified")
				}
				continue
			}
			want := append([]byte(nil), w...) // as sent, TTL decremented
			for j := range w {
				w[j] = 0xa5 // the caller reuses its buffer at once
			}
			n, err := lb.ReadPacket(buf)
			if err != nil || !bytes.Equal(buf[:n], want) {
				t.Fatalf("sent %x, received %x (%v)", want, buf[:n], err)
			}
			if w0 := pkt[0] >> 4; w0 == 4 && want[8] != pkt[8]-1 || w0 == 6 && want[7] != pkt[7]-1 {
				t.Fatal("TTL not decremented by one")
			}
		}
	})
}

func FuzzCapsuleStreamRead(f *testing.F) {
	f.Add(slices.Concat(capsule(capsuleDatagram, []byte{0, 1, 2, 3}), capsule(capsuleBGPing, nil), capsule(capsuleDatagram, []byte{2, 100, 96, 0, 2, 4, 0, 9})))
	f.Add([]byte{0x80, 0x01, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, stream []byte) {
		c, s := net.Pipe()
		cs := newCapsuleStream(s, nil, 5*time.Second)
		go func() {
			_, _ = c.Write(stream)
			_ = c.Close()
		}()
		for i := 0; ; i++ {
			b, err := cs.ReceiveDatagram(context.Background())
			if err != nil {
				break
			}
			if len(b) > maxDatagramLen || i > len(stream) {
				t.Fatalf("datagram %d of %d bytes", i, len(b))
			}
		}
		_ = cs.Close()
	})
}

func FuzzParseRelayPath(f *testing.F) {
	f.Add(relayPath(netip.MustParseAddr("100.96.0.9")))
	f.Add("/.well-known/masque/udp/100.96.0.9/443")
	f.Add("/.well-known/masque/udp/::1/443/")
	f.Fuzz(func(t *testing.T, p string) {
		a, err := parseRelayPath(p)
		if err != nil {
			return
		}
		if !a.Is4() {
			t.Fatalf("%q names %s", p, a)
		}
		if b, err := parseRelayPath(relayPath(a)); err != nil || b != a {
			t.Fatalf("%s does not survive a round trip: %s %v", a, b, err)
		}
	})
}

func FuzzParseDNSHeader(f *testing.F) {
	f.Add("10.0.0.53, fd00::53")
	f.Add("::ffff:10.0.0.1,,x")
	f.Fuzz(func(t *testing.T, v string) {
		as := parseDNSHeader(v)
		if again := parseDNSHeader(dnsHeader(as)); !slices.Equal(again, as) {
			t.Fatalf("%v does not survive a round trip: %v", as, again)
		}
	})
}

// fakeStream is a relay stream fed by the test.
type fakeStream struct {
	in   chan []byte
	done chan struct{}
	once sync.Once
	ack  chan struct{} // a receive after the last datagram: the loop handled it

	mu   sync.Mutex
	sent [][]byte
}

func newFakeStream() *fakeStream {
	return &fakeStream{in: make(chan []byte), done: make(chan struct{}), ack: make(chan struct{}, 1)}
}

func (s *fakeStream) SendDatagram(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, append([]byte(nil), b...))
	return nil
}

func (s *fakeStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case s.ack <- struct{}{}:
	default:
	}
	select {
	case b := <-s.in:
		return b, nil
	case <-s.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fakeStream) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *fakeStream) waitEnd() { <-s.done }

// feed hands the datagrams to the stream's reader and returns once the
// reader has handled all of them.
func (s *fakeStream) feed(dgs [][]byte) {
	for _, d := range dgs {
		<-s.ack
		s.in <- d
	}
	<-s.ack
}

func (s *fakeStream) got() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

// splitDatagrams cuts data into datagrams, each behind a one-byte length.
func splitDatagrams(data []byte) [][]byte {
	var out [][]byte
	for len(data) > 0 {
		n := min(int(data[0]), len(data)-1)
		out = append(out, append([]byte(nil), data[1:1+n]...))
		data = data[1+n:]
	}
	return out
}

func joinDatagrams(dgs ...[]byte) []byte {
	var out []byte
	for _, d := range dgs {
		out = append(append(out, byte(len(d))), d...)
	}
	return out
}

// The hub moves datagrams between a dialer and a listener; both sides are
// authenticated nodes, but what they send is theirs to choose.
func FuzzRelayForward(f *testing.F) {
	src := netip.MustParseAddr("100.96.0.2")
	head := []byte{ctxListen, 100, 96, 0, 2, 0x04, 0x00} // src:1024, the first dialer's port
	f.Add(joinDatagrams(append(slices.Clone(head), "to the dialer"...), append([]byte{ctxListen, 100, 96, 0, 2, 0x04, 0x01}, "nobody"...), []byte{ctxListen}),
		joinDatagrams(append([]byte{ctxDial}, "to the listener"...), []byte{ctxListen, 1}, nil))
	f.Fuzz(func(t *testing.T, fromListener, fromDialer []byte) {
		s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		s.relay.listeners = make(map[netip.Addr]*relayListener)
		target := netip.MustParseAddr("100.96.0.9")
		lst, dl := newFakeStream(), newFakeStream()
		lctx, lcancel := context.WithCancel(context.Background())
		defer lcancel()
		lend := make(chan struct{})
		go func() {
			s.relayListen(lctx, lcancel, lst, AuthenticatedPeer{deviceID: "listener"}, target)
			close(lend)
		}()
		for s.relayRoom(target) != 200 {
			time.Sleep(time.Millisecond)
		}
		dctx, dcancel := context.WithCancel(context.Background())
		defer dcancel()
		dend := make(chan struct{})
		go func() {
			s.relayDialOn(dctx, dcancel, dl, AuthenticatedPeer{deviceID: "dialer"}, src, target)
			close(dend)
		}()
		for {
			s.relay.mu.Lock()
			n := len(s.relay.listeners[target].dialers)
			s.relay.mu.Unlock()
			if n == 1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		ldg, ddg := splitDatagrams(fromListener), splitDatagrams(fromDialer)
		var wantDialer, wantListener [][]byte
		for _, b := range ldg {
			if len(b) >= 7 && bytes.Equal(b[:7], head) {
				wantDialer = append(wantDialer, append([]byte{ctxDial}, b[7:]...))
			}
		}
		for _, b := range ddg {
			if len(b) >= 1 && b[0] == ctxDial {
				wantListener = append(wantListener, append(slices.Clone(head), b[1:]...))
			}
		}
		lst.feed(ldg)
		dl.feed(ddg)
		_ = dl.Close()
		<-dend
		_ = lst.Close()
		<-lend
		if got := dl.got(); !slices.EqualFunc(got, wantDialer, bytes.Equal) {
			t.Fatalf("dialer got %x, want %x", got, wantDialer)
		}
		if got := lst.got(); !slices.EqualFunc(got, wantListener, bytes.Equal) {
			t.Fatalf("listener got %x, want %x", got, wantListener)
		}
	})
}

// WriteTo refuses an address that is not a UDP address instead of
// dereferencing the nil the failed type assertion leaves.
func TestRelayConnWriteToForeignAddr(t *testing.T) {
	c := &relayConn{str: newFakeStream(), listen: true, closed: make(chan struct{}), deadline: newDeadline()}
	if _, err := c.WriteTo([]byte{1}, &net.TCPAddr{IP: net.IPv4(100, 96, 0, 2), Port: 443}); err == nil {
		t.Fatal("a TCP address was accepted")
	}
	if _, err := c.WriteTo([]byte{1}, &net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: 443}); err == nil {
		t.Fatal("an IPv6 address was accepted")
	}
}

// A node's end of a relay stream turns datagrams into packets for its QUIC
// transport.
func FuzzRelayConn(f *testing.F) {
	f.Add(joinDatagrams([]byte{ctxDial, 1, 2, 3}, []byte{ctxListen, 100, 96, 0, 2, 4, 0, 9}), false)
	f.Add(joinDatagrams([]byte{ctxListen, 100, 96, 0, 2, 4, 0, 9}, []byte{ctxListen, 1}), true)
	f.Fuzz(func(t *testing.T, data []byte, listen bool) {
		str := newFakeStream()
		self, peer := netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("100.96.0.9")
		c := &relayConn{str: str, listen: listen, local: &net.UDPAddr{IP: self.AsSlice(), Port: RelayPort}, peer: &net.UDPAddr{IP: peer.AsSlice(), Port: RelayPort},
			in: make(chan relayPacket, 256), closed: make(chan struct{}), deadline: newDeadline()}
		go c.receive()
		dgs := splitDatagrams(data)
		str.feed(dgs)
		buf := make([]byte, 2048)
		_ = c.SetReadDeadline(time.Now().Add(-time.Second))
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				break
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok || len(ua.IP) != 4 && len(ua.IP) != 16 || n > len(buf) {
				t.Fatalf("packet of %d bytes from %v", n, from)
			}
			if _, err := c.WriteTo(buf[:n], from); err != nil {
				t.Fatal(err)
			}
		}
		_ = c.Close()
	})
}
