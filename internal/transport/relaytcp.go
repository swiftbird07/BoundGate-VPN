package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// A relay stream carries the datagrams of one relayed path: over QUIC an
// HTTP/3 request stream (RFC 9298), over the TCP fallback a second TLS
// connection to the same hub that is upgraded to connect-udp and then speaks
// DATAGRAM capsules (RFC 9297). The bytes inside are the same on both, so
// the relay code above does not care which one it holds.
type relayStream interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Close() error
	// waitEnd returns when the other end finished the stream.
	waitEnd()
}

// ---- QUIC ----

// h3Stream is the hub's side of a relay stream.
type h3Stream struct{ str *http3.Stream }

func (s h3Stream) SendDatagram(b []byte) error { return s.str.SendDatagram(b) }
func (s h3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.str.ReceiveDatagram(ctx)
}
func (s h3Stream) Close() error { return s.str.Close() }
func (s h3Stream) waitEnd()     { _, _ = io.Copy(io.Discard, s.str) }

// h3Request is a node's side of a relay stream.
type h3Request struct{ str *http3.RequestStream }

func (s h3Request) SendDatagram(b []byte) error { return s.str.SendDatagram(b) }
func (s h3Request) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.str.ReceiveDatagram(ctx)
}
func (s h3Request) Close() error {
	s.str.CancelRead(0)
	return s.str.Close()
}
func (s h3Request) waitEnd() { _, _ = io.Copy(io.Discard, s.str) }

// ---- TCP fallback ----

// capsuleStream is a relay stream on a byte stream: every datagram is one
// DATAGRAM capsule whose payload is what the QUIC side puts in an HTTP
// datagram (context ID and the rest), so both transports carry the same
// bytes. Unlike capsuleLink it knows nothing of IP packets or routes: the
// relay only moves payloads.
type capsuleStream struct {
	conn net.Conn
	r    *bufio.Reader
	idle time.Duration

	wmu  sync.Mutex
	wbuf []byte

	in   chan []byte
	done chan struct{}
	once sync.Once
}

func newCapsuleStream(conn net.Conn, r *bufio.Reader, idle time.Duration) *capsuleStream {
	if r == nil {
		r = bufio.NewReaderSize(conn, 64<<10)
	}
	if idle <= 0 {
		idle = 60 * time.Second // as ClientConfig and ServerConfig default it
	}
	s := &capsuleStream{conn: conn, r: r, idle: idle, in: make(chan []byte, capsuleQueue), done: make(chan struct{})}
	go s.readLoop()
	return s
}

func (s *capsuleStream) readLoop() {
	defer s.Close()
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.idle))
		typ, err := quicvarint.Read(s.r)
		if err != nil {
			return
		}
		n, err := quicvarint.Read(s.r)
		if err != nil {
			return
		}
		if n > maxDatagramLen {
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(s.r, b); err != nil {
			return
		}
		if typ != capsuleDatagram { // RFC 9297: skip what we do not know
			continue
		}
		select {
		case s.in <- b:
		case <-s.done:
			return
		default: // a full queue drops, like a socket buffer
		}
	}
}

func (s *capsuleStream) SendDatagram(b []byte) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.wbuf = s.wbuf[:0]
	s.wbuf = quicvarint.Append(s.wbuf, capsuleDatagram)
	s.wbuf = quicvarint.Append(s.wbuf, uint64(len(b)))
	s.wbuf = append(s.wbuf, b...)
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.idle))
	_, err := s.conn.Write(s.wbuf)
	return err
}

func (s *capsuleStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-s.in:
		return b, nil
	case <-s.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *capsuleStream) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
	return nil
}

func (s *capsuleStream) waitEnd() { <-s.done }

// handleRelayTCP is handleRelay for the TCP fallback: the same checks, the
// same authorisation, an HTTP/1.1 upgrade instead of extended CONNECT.
func (s *Server) handleRelayTCP(w http.ResponseWriter, r *http.Request, peer AuthenticatedPeer) {
	rh, ok := s.h.(RelayHandler)
	if !ok {
		http.Error(w, "this hub does not relay", http.StatusNotImplemented)
		return
	}
	target, err := parseRelayPath(r.URL.Path)
	if err != nil {
		s.log.Warn("transport: bad relay request", "peer", peer, "err", err, "transport", "tcp")
		http.Error(w, "target must be an overlay address", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), relayProtocol) ||
		!headerHasToken(r.Header.Get("Connection"), "upgrade") || r.Header.Get("Capsule-Protocol") != "?1" {
		http.Error(w, "expected an upgrade to connect-udp", http.StatusBadRequest)
		return
	}
	listen := r.Header.Get(relayBindHeader) == "?1"
	var src netip.Addr
	status := http.StatusOK
	if listen {
		status = rh.RelayListen(peer, target)
	} else if src, status = rh.RelayDial(peer, target); status == http.StatusOK {
		status = s.relayRoom(target)
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		s.log.Error("transport: hijack failed", "peer", peer, "err", err)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	head := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + relayProtocol + "\r\nCapsule-Protocol: ?1\r\n\r\n"
	if _, err := rw.WriteString(head); err != nil || rw.Flush() != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	str := newCapsuleStream(conn, rw.Reader, s.cfg.IdleTimeout)
	defer str.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if listen {
		s.relayListen(ctx, cancel, str, peer, target)
		return
	}
	s.relayDialOn(ctx, cancel, str, peer, src, target)
}

// dialRelayTCP opens a relay stream on a second TLS connection to the hub,
// upgraded to connect-udp. A node on the TCP fallback has no stream to spare
// on its tunnel: capsules there carry its IP packets.
func dialRelayTCP(ctx context.Context, cfg ClientConfig, target netip.Addr, listen bool) (relayStream, error) {
	if cfg.TLS == nil || len(cfg.TLS.Certificates) == 0 {
		return nil, errors.New("transport: relay over TCP needs the tunnel's TLS configuration")
	}
	cfg = cfg.withDefaults()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: cfg.HandshakeTimeout, KeepAlive: cfg.KeepAlive}, Config: tcpTLSConfig(cfg.TLS)}
	hctx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	raw, err := d.DialContext(hctx, "tcp", cfg.GatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: relay dial tcp %s: %w", cfg.GatewayAddr, err)
	}
	conn := raw.(*tls.Conn)
	h := http.Header{"Connection": {"Upgrade"}, "Upgrade": {relayProtocol}, "Capsule-Protocol": {"?1"}}
	if listen {
		h.Set(relayBindHeader, "?1")
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: cfg.TLS.ServerName, Path: relayPath(target)},
		Host:   cfg.TLS.ServerName,
		Header: h,
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("transport: relay request: %w", err)
	}
	r := bufio.NewReaderSize(conn, 64<<10)
	rsp, err := http.ReadResponse(r, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("transport: relay response: %w", err)
	}
	if rsp.StatusCode != http.StatusSwitchingProtocols {
		_ = rsp.Body.Close()
		_ = conn.Close()
		return nil, &RelayError{Status: rsp.StatusCode}
	}
	if !strings.EqualFold(rsp.Header.Get("Upgrade"), relayProtocol) {
		_ = conn.Close()
		return nil, &RelayError{Status: rsp.StatusCode}
	}
	_ = conn.SetDeadline(time.Time{})
	return newCapsuleStream(conn, r, cfg.IdleTimeout), nil
}
