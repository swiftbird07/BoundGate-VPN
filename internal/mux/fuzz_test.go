package mux

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// clientInitials are the first datagrams a quic-go client sends to name:
// with post-quantum key shares the ClientHello spans two Initial packets.
func clientInitials(tb testing.TB, name string, v quic.Version) [][]byte {
	tb.Helper()
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	defer sink.Close()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	defer tr.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = tr.Dial(ctx, sink.LocalAddr(), &tls.Config{ServerName: name, NextProtos: []string{"h3"}}, &quic.Config{Versions: []quic.Version{v}})
	}()
	var out [][]byte
	buf := make([]byte, 2048)
	for len(out) < 2 {
		_ = sink.SetReadDeadline(time.Now().Add(time.Second))
		n, err := sink.Read(buf)
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
	if len(out) == 0 {
		tb.Fatal("no Initial captured")
	}
	return out
}

func testFront(tb testing.TB) *Front {
	tb.Helper()
	fr := &Front{cfg: Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		byID: map[byte]*backend{}, byName: map[string]*backend{}, wild: map[string]*backend{}, initial: map[flowKey]*flow{}}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { conn.Close() })
	be := &backend{route: Route{Name: "hub", ID: 7}, conn: conn}
	fr.byID[7], fr.byName["hub.boundgate"], fr.wild[".example.com"] = be, be, be
	return fr
}

// Two datagrams of one handshake from the internet. What the front holds
// back for later must be its own copy: fromClients reads every datagram
// into the same buffer.
func FuzzQUICInitial(f *testing.F) {
	for _, v := range []quic.Version{quic.Version1, quic.Version2} {
		in := clientInitials(f, "hub.boundgate", v)
		if len(in) == 1 {
			in = append(in, nil)
		}
		f.Add(in[0], in[1])
	}
	in := clientInitials(f, "nodes.example.com", quic.Version1)
	f.Add(in[0], []byte{0x40, 7, 1, 2, 3, 4, 5, 6, 7, 8})
	client := netip.MustParseAddrPort("192.0.2.1:4000")
	f.Fuzz(func(t *testing.T, first, second []byte) {
		for _, b := range [][]byte{first, second} {
			h, err := parseLongHeader(b)
			if err != nil {
				continue
			}
			if len(h.dcid) > 20 || h.initial && (h.pnOffset < 7 || h.pnOffset > h.packetEnd || h.packetEnd > len(b)) {
				t.Fatalf("header %+v of a %d byte datagram", h, len(b))
			}
		}
		fr := testFront(t)
		kept := append([]byte(nil), first...)
		_, held := fr.routeUDP(client, first)
		for i := range first {
			first[i] = 0xa5
		}
		if len(held) > 0 {
			t.Fatal("datagrams handed out before they were held")
		}
		_, held = fr.routeUDP(client, second)
		for _, h := range held {
			if !bytes.Equal(h, kept) {
				t.Fatalf("held datagram %x is not what arrived (%x)", h, kept)
			}
		}
		if len(fr.initial) > maxFlows {
			t.Fatal("flow table beyond its bound")
		}
		for _, fl := range fr.initial {
			if len(fl.held) > maxHeld || len(fl.crypto.data) > cryptoBufMax || len(fl.crypto.data) != len(fl.crypto.have) {
				t.Fatalf("flow holds %d datagrams, %d crypto bytes", len(fl.held), len(fl.crypto.data))
			}
		}
	})
}

// The front peeks the ClientHello of every TCP connection from the
// internet and replays exactly what it read to the backend.
func FuzzReadTLSClientHello(f *testing.F) {
	c, s := net.Pipe()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: "Nodes.BG.example.com", InsecureSkipVerify: true}).Handshake()
		c.Close()
	}()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, hello, err := readTLSClientHello(s, tcpPeekMax)
	s.Close()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hello)
	f.Add(append(append([]byte{}, hello[:5+40]...), 0x16, 3, 1, 0, 10))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		name, raw, err := readTLSClientHello(bytes.NewReader(b), tcpPeekMax)
		if !bytes.HasPrefix(b, raw) {
			t.Fatalf("replays %x, never received", raw[min(len(raw), len(b)):])
		}
		if (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) && len(raw) != len(b) {
			t.Fatalf("read all %d bytes, replays %d", len(b), len(raw))
		}
		if err == nil {
			if n, err := validName(name); err != nil || n != name {
				t.Fatalf("name %q", name)
			}
		}
		if len(raw) > tcpPeekMax+5 {
			t.Fatalf("peeked %d bytes", len(raw))
		}
	})
}

// A connection that ends (or stalls past the peek deadline) inside a record
// is replayed with exactly the bytes that arrived: neither the zeros of the
// unfilled record buffer nor fewer.
func TestReadTLSClientHelloReplaysWhatArrived(t *testing.T) {
	part := []byte{0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x01, 0x00, 0x03, 0x03}
	incomplete := []byte{0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x01, 0x00, 0x03, 0x03}
	for _, in := range [][]byte{part, append(append([]byte{}, incomplete...), 0x16, 0x03, 0x01)} {
		_, raw, err := readTLSClientHello(bytes.NewReader(in), tcpPeekMax)
		if err == nil || !bytes.Equal(raw, in) {
			t.Fatalf("read %x, replays %x (%v)", in, raw, err)
		}
	}
}

// A PROXY header comes from a trusted front, but the connection behind it
// comes from the internet; neither may break the reader.
func FuzzProxyConn(f *testing.F) {
	f.Add(append(ProxyV2Header(&net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 40000}, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}), "\x16\x03\x01"...))
	f.Add(append(ProxyV2Header(&net.TCPAddr{IP: net.ParseIP("2001:db8::9"), Port: 40000}, &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}), "rest"...))
	f.Add(append(ProxyV2Header(nil, nil), "local"...))
	f.Add([]byte("PROXY TCP4 203.0.113.9 10.20.1.204 40000 8080\r\nrest"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add([]byte("\x16\x03\x01 hello"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, s := net.Pipe()
		go func() {
			_, _ = c.Write(b)
			c.Close()
		}()
		pc := &proxyConn{Conn: s}
		remote := pc.RemoteAddr()
		rest, _ := io.ReadAll(pc)
		pc.Close()
		if remote == nil {
			t.Fatal("no remote address")
		}
		if pc.remote != nil {
			ta, ok := pc.remote.(*net.TCPAddr)
			if !ok || ta.AddrPort().Addr().Is4In6() {
				t.Fatalf("remote %v", pc.remote)
			}
		}
		if len(b) >= 6 && !bytes.HasPrefix(b, []byte("PROXY ")) && !bytes.HasPrefix(b, proxyV2Sig[:6]) && !bytes.Equal(rest, b) {
			t.Fatal("a connection without a header lost bytes")
		}
		if pc.err == nil && !bytes.HasSuffix(b, rest) {
			t.Fatal("payload is not the end of the stream")
		}
	})
}

func FuzzEncap(f *testing.F) {
	frame := make([]byte, encapLen+3)
	putEncap(frame, netip.MustParseAddrPort("192.0.2.1:4000"))
	f.Add(frame)
	putEncap(frame, netip.MustParseAddrPort("[2001:db8::1]:443"))
	f.Add(frame)
	f.Fuzz(func(t *testing.T, b []byte) {
		ap, payload, err := getEncap(b)
		if err != nil {
			return
		}
		if !bytes.Equal(payload, b[encapLen:]) {
			t.Fatal("payload")
		}
		again := make([]byte, encapLen)
		putEncap(again, ap)
		// family 6 with a v4-mapped address comes back as family 4: the same client
		if ap2, _, err := getEncap(again); err != nil || ap2.Addr() != ap.Addr().Unmap() || ap2.Port() != ap.Port() {
			t.Fatalf("%v does not survive a round trip: %v %v", ap, ap2, err)
		}
	})
}
