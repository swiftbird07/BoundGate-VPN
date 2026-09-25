package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// CONNECT-IP over a byte stream (RFC 9484 §4 with HTTP/1.1, RFC 9297
// capsules): the TCP/443 fallback for networks that block UDP. The capsule
// types are the standard ones; two private types carry what QUIC has and a
// stream has not: a close code and a keep-alive.
const (
	capsuleDatagram uint64 = 0x00     // RFC 9297: context ID + IP packet
	capsuleAssign   uint64 = 0x01     // RFC 9484 ADDRESS_ASSIGN
	capsuleRequest  uint64 = 0x02     // RFC 9484 ADDRESS_REQUEST (ignored)
	capsuleRoutes   uint64 = 0x03     // RFC 9484 ROUTE_ADVERTISEMENT
	capsuleBGClose  uint64 = 0x2f4a2f // private: varint code + reason; the stream ends after it
	capsuleBGPing   uint64 = 0x2f4a30 // private: empty; keeps NATs and idle timers alive
	maxDatagramLen         = 1 << 16
	maxControlLen          = 1 << 20
	capsuleQueue           = 256
)

// CloseError is why a stream tunnel ended: the peer's close capsule
// (Remote) or this side's Close.
type CloseError struct {
	Code   quic.ApplicationErrorCode
	Reason string
	Remote bool
}

func (e *CloseError) Error() string {
	who := "local"
	if e.Remote {
		who = "peer"
	}
	return fmt.Sprintf("tunnel closed by %s (code %d): %s", who, e.Code, e.Reason)
}

// capsuleLink is one CONNECT-IP session on a byte stream, after the HTTP
// upgrade. Both ends of the stream use it.
type capsuleLink struct {
	conn        net.Conn
	r           *bufio.Reader
	idleTimeout time.Duration
	keepAlive   time.Duration

	wmu  sync.Mutex
	wbuf []byte
	in   chan []byte
	// out holds datagram capsules for writeLoop. WritePacket never waits
	// for the peer: a full queue drops the packet, as a congested QUIC path
	// would. The hub writes into every link from one goroutine, so one peer
	// that stops reading must not stop the others.
	out     chan []byte
	dropped atomic.Uint64
	done    chan struct{}
	once    sync.Once
	stopKA  chan struct{} // closed by Close: stops the keepalive and a read loop waiting to queue
	server  bool

	mu        sync.Mutex
	err       error // why the stream ended (set before done is closed)
	closeErr  *CloseError
	prefixes  []netip.Prefix
	routes    []connectip.IPRoute
	gotAssign chan struct{}
	gotRoutes chan struct{}
}

// server: the hub's end, which only sends ADDRESS_ASSIGN and
// ROUTE_ADVERTISEMENT; what a client sends of them is skipped unread.
func newCapsuleLink(conn net.Conn, r *bufio.Reader, idle, keepAlive time.Duration, server bool) *capsuleLink {
	if r == nil {
		r = bufio.NewReaderSize(conn, 64<<10)
	}
	l := &capsuleLink{
		conn: conn, r: r, idleTimeout: idle, keepAlive: keepAlive, server: server,
		in: make(chan []byte, capsuleQueue), out: make(chan []byte, capsuleQueue), done: make(chan struct{}), stopKA: make(chan struct{}),
		gotAssign: make(chan struct{}), gotRoutes: make(chan struct{}),
	}
	go l.readLoop()
	go l.writeLoop()
	go l.keepAliveLoop()
	return l
}

// writeLoop sends the queued datagram capsules, several per write when they
// pile up. A write that fails or does not finish within the idle timeout
// ends the stream.
func (l *capsuleLink) writeLoop() {
	var batch []byte
	for {
		var b []byte
		select {
		case b = <-l.out:
		case <-l.done:
			return
		}
		batch = append(batch[:0], b...)
	more:
		for len(batch) < 64<<10 {
			select {
			case b = <-l.out:
				batch = append(batch, b...)
			default:
				break more
			}
		}
		l.wmu.Lock()
		_ = l.conn.SetWriteDeadline(time.Now().Add(l.idleTimeout))
		_, err := l.conn.Write(batch)
		l.wmu.Unlock()
		if err != nil {
			_ = l.conn.Close() // the read loop ends and records why
			return
		}
	}
}

// readLoop parses capsules until the stream ends. Datagrams queue for
// ReadPacket; control capsules update the link; unknown ones are skipped, as
// RFC 9297 requires.
func (l *capsuleLink) readLoop() {
	var err error
	defer func() {
		l.mu.Lock()
		if l.err == nil {
			l.err = err
		}
		l.mu.Unlock()
		_ = l.conn.Close()
		close(l.done)
	}()
	for {
		_ = l.conn.SetReadDeadline(time.Now().Add(l.idleTimeout))
		typ, e := quicvarint.Read(l.r)
		if e != nil {
			err = e
			return
		}
		n, e := quicvarint.Read(l.r)
		if e != nil {
			err = e
			return
		}
		switch typ {
		case capsuleDatagram:
			if n > maxDatagramLen {
				err = fmt.Errorf("transport: datagram capsule of %d bytes", n)
				return
			}
			b := make([]byte, n)
			if _, e := io.ReadFull(l.r, b); e != nil {
				err = e
				return
			}
			ctxID, m, e := quicvarint.Parse(b)
			if e != nil || ctxID != 0 || m == len(b) {
				continue // not an IP packet in context 0: dropped, like connect-ip-go does
			}
			select {
			case l.in <- b[m:]:
			case <-l.stopKA:
				return // closed while nobody reads the queue: Close waits for this loop
			}
		case capsuleAssign, capsuleRoutes, capsuleBGClose:
			if n > maxControlLen {
				err = fmt.Errorf("transport: control capsule of %d bytes", n)
				return
			}
			if l.server && typ != capsuleBGClose {
				if _, e := io.CopyN(io.Discard, l.r, int64(n)); e != nil {
					err = e
					return
				}
				continue
			}
			b := make([]byte, n)
			if _, e := io.ReadFull(l.r, b); e != nil {
				err = e
				return
			}
			switch typ {
			case capsuleAssign:
				ps, e := parseAssign(b)
				if e != nil {
					err = e
					return
				}
				l.mu.Lock()
				first := l.prefixes == nil
				l.prefixes = ps
				l.mu.Unlock()
				if first {
					close(l.gotAssign)
				}
			case capsuleRoutes:
				rs, e := parseRoutes(b)
				if e != nil {
					err = e
					return
				}
				l.mu.Lock()
				first := l.routes == nil
				l.routes = rs
				l.mu.Unlock()
				if first {
					close(l.gotRoutes)
				}
			case capsuleBGClose:
				code, m, e := quicvarint.Parse(b)
				if e != nil {
					err = e
					return
				}
				ce := &CloseError{Code: quic.ApplicationErrorCode(code), Reason: string(b[m:]), Remote: true}
				l.mu.Lock()
				if l.closeErr == nil {
					l.closeErr = ce
				}
				l.mu.Unlock()
				err = ce
				return
			}
		default:
			if _, e := io.CopyN(io.Discard, l.r, int64(n)); e != nil {
				err = e
				return
			}
		}
	}
}

func (l *capsuleLink) keepAliveLoop() {
	if l.keepAlive <= 0 {
		return
	}
	t := time.NewTicker(l.keepAlive)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := l.writeCapsule(capsuleBGPing, nil); err != nil {
				return
			}
		case <-l.stopKA:
			return
		case <-l.done:
			return
		}
	}
}

// writeCapsule sends one capsule as a single write.
func (l *capsuleLink) writeCapsule(typ uint64, payload []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.wbuf = l.wbuf[:0]
	l.wbuf = quicvarint.Append(l.wbuf, typ)
	l.wbuf = quicvarint.Append(l.wbuf, uint64(len(payload)))
	l.wbuf = append(l.wbuf, payload...)
	_ = l.conn.SetWriteDeadline(time.Now().Add(l.idleTimeout))
	_, err := l.conn.Write(l.wbuf)
	return err
}

// ReadPacket returns the next IP packet from the peer.
func (l *capsuleLink) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-l.in:
		return copy(b, p), nil
	case <-l.done:
		select {
		case p := <-l.in: // packets that arrived before the end are still delivered
			return copy(b, p), nil
		default:
		}
		return 0, l.Err()
	}
}

// WritePacket sends one IP packet, decrementing the TTL like the QUIC path
// does (connect-ip-go) so both transports behave the same.
func (l *capsuleLink) WritePacket(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl || b[8] <= 1 {
			return nil, nil
		}
		b[8]--
		b[10], b[11] = 0, 0
		var sum uint32
		for i := 0; i+1 < ihl; i += 2 { // the whole header, options included
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		for sum > 0xffff {
			sum = sum&0xffff + sum>>16
		}
		cs := ^uint16(sum)
		b[10], b[11] = byte(cs>>8), byte(cs)
	case 6:
		if len(b) < 40 || b[7] <= 1 {
			return nil, nil
		}
		b[7]--
	default:
		return nil, nil
	}
	c := make([]byte, 0, len(b)+10)
	c = quicvarint.Append(c, capsuleDatagram)
	c = quicvarint.Append(c, uint64(1+len(b)))
	c = append(c, 0) // context ID 0
	c = append(c, b...)
	select {
	case <-l.done:
		return nil, l.Err()
	default:
	}
	select {
	case l.out <- c:
	default:
		l.dropped.Add(1)
	}
	return nil, nil
}

// Done is closed when the stream has ended.
func (l *capsuleLink) Done() <-chan struct{} { return l.done }

// Err is why the stream ended, nil while it lives.
func (l *capsuleLink) Err() error {
	select {
	case <-l.done:
	default:
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closeErr != nil {
		return l.closeErr
	}
	if l.err == nil {
		return io.EOF
	}
	return l.err
}

// Close sends a close capsule (best effort) and ends the stream.
func (l *capsuleLink) Close(code quic.ApplicationErrorCode, reason string) error {
	l.once.Do(func() {
		close(l.stopKA)
		l.mu.Lock()
		if l.closeErr == nil {
			l.closeErr = &CloseError{Code: code, Reason: reason}
		}
		l.mu.Unlock()
		payload := quicvarint.Append(nil, uint64(code))
		payload = append(payload, reason...)
		// a write that waits for a peer which stopped reading gives up now,
		// so that closing (a revocation) never waits for it
		_ = l.conn.SetWriteDeadline(time.Now())
		l.wmu.Lock()
		_ = l.conn.SetWriteDeadline(time.Now().Add(time.Second))
		b := quicvarint.Append(nil, capsuleBGClose)
		b = quicvarint.Append(b, uint64(len(payload)))
		_, _ = l.conn.Write(append(b, payload...))
		l.wmu.Unlock()
		_ = l.conn.Close()
	})
	<-l.done
	return nil
}

// AssignAddresses sends ADDRESS_ASSIGN (server side).
func (l *capsuleLink) AssignAddresses(prefixes []netip.Prefix) error {
	var b []byte
	for _, p := range prefixes {
		b = quicvarint.Append(b, 0) // request ID 0: not in answer to a request
		b = appendPrefix(b, p)
	}
	return l.writeCapsule(capsuleAssign, b)
}

// AdvertiseRoute sends ROUTE_ADVERTISEMENT (server side).
func (l *capsuleLink) AdvertiseRoute(routes []connectip.IPRoute) error {
	var b []byte
	for _, r := range routes {
		if r.StartIP.Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, r.StartIP.AsSlice()...)
		b = append(b, r.EndIP.AsSlice()...)
		b = append(b, r.IPProtocol)
	}
	return l.writeCapsule(capsuleRoutes, b)
}

// LocalPrefixes waits for the first ADDRESS_ASSIGN (client side).
func (l *capsuleLink) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-l.gotAssign:
	case <-l.done:
		return nil, l.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prefixes, nil
}

// Routes waits for the first ROUTE_ADVERTISEMENT (client side).
func (l *capsuleLink) Routes(ctx context.Context) ([]connectip.IPRoute, error) {
	select {
	case <-l.gotRoutes:
	case <-l.done:
		return nil, l.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.routes, nil
}

func appendPrefix(b []byte, p netip.Prefix) []byte {
	if p.Addr().Is4() {
		b = append(b, 4)
	} else {
		b = append(b, 6)
	}
	b = append(b, p.Addr().AsSlice()...)
	return append(b, byte(p.Bits()))
}

// parseAssign decodes ADDRESS_ASSIGN: (request ID, version, address, prefix length)*.
func parseAssign(b []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for len(b) > 0 {
		_, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("transport: ADDRESS_ASSIGN: %w", err)
		}
		b = b[n:]
		p, rest, err := parsePrefix(b)
		if err != nil {
			return nil, fmt.Errorf("transport: ADDRESS_ASSIGN: %w", err)
		}
		out = append(out, p)
		b = rest
	}
	if out == nil {
		out = []netip.Prefix{}
	}
	return out, nil
}

func parsePrefix(b []byte) (netip.Prefix, []byte, error) {
	if len(b) < 1 {
		return netip.Prefix{}, nil, errors.New("truncated")
	}
	var alen int
	switch b[0] {
	case 4:
		alen = 4
	case 6:
		alen = 16
	default:
		return netip.Prefix{}, nil, fmt.Errorf("IP version %d", b[0])
	}
	if len(b) < 1+alen+1 {
		return netip.Prefix{}, nil, errors.New("truncated")
	}
	addr, _ := netip.AddrFromSlice(b[1 : 1+alen])
	bits := int(b[1+alen])
	p := netip.PrefixFrom(addr, bits)
	if !p.IsValid() || p.Masked() != p {
		return netip.Prefix{}, nil, fmt.Errorf("prefix %s/%d", addr, bits)
	}
	return p, b[1+alen+1:], nil
}

// parseRoutes decodes ROUTE_ADVERTISEMENT: (version, start, end, protocol)*.
func parseRoutes(b []byte) ([]connectip.IPRoute, error) {
	var out []connectip.IPRoute
	for len(b) > 0 {
		var alen int
		switch b[0] {
		case 4:
			alen = 4
		case 6:
			alen = 16
		default:
			return nil, fmt.Errorf("transport: ROUTE_ADVERTISEMENT: IP version %d", b[0])
		}
		if len(b) < 1+2*alen+1 {
			return nil, errors.New("transport: ROUTE_ADVERTISEMENT: truncated")
		}
		start, _ := netip.AddrFromSlice(b[1 : 1+alen])
		end, _ := netip.AddrFromSlice(b[1+alen : 1+2*alen])
		if end.Less(start) {
			return nil, errors.New("transport: ROUTE_ADVERTISEMENT: end before start")
		}
		out = append(out, connectip.IPRoute{StartIP: start, EndIP: end, IPProtocol: b[1+2*alen]})
		b = b[1+2*alen+1:]
	}
	if out == nil {
		out = []connectip.IPRoute{}
	}
	return out, nil
}
