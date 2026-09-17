package mux

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// PROXY protocol v2 (haproxy.org/download/2.9/doc/proxy-protocol.txt): what
// the front, or any TCP reverse proxy in SNI-passthrough mode, puts before
// the client's bytes so the server learns who is calling.

var proxyV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ProxyV2Header builds the header for a proxied TCP connection.
func ProxyV2Header(src, dst net.Addr) []byte {
	s, ok1 := src.(*net.TCPAddr)
	d, ok2 := dst.(*net.TCPAddr)
	out := append([]byte(nil), proxyV2Sig...)
	if !ok1 || !ok2 {
		return append(out, 0x20, 0x00, 0, 0) // LOCAL
	}
	sa, da := s.AddrPort(), d.AddrPort()
	if sa.Addr().Unmap().Is4() && da.Addr().Unmap().Is4() {
		out = append(out, 0x21, 0x11, 0, 12)
		a, b := sa.Addr().Unmap().As4(), da.Addr().Unmap().As4()
		out = append(append(out, a[:]...), b[:]...)
	} else {
		out = append(out, 0x21, 0x21, 0, 36)
		a, b := sa.Addr().As16(), da.Addr().As16()
		out = append(append(out, a[:]...), b[:]...)
	}
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(out, sa.Port()), da.Port())
}

// ProxyListener accepts PROXY v2 headers from trusted sources and reports
// the carried address as RemoteAddr. Connections from anyone else pass
// through unchanged, so a server can be reachable both ways; a trusted
// source that sends no header is refused.
type ProxyListener struct {
	net.Listener
	Trusted []netip.Prefix
}

// Accept implements net.Listener.
func (l *ProxyListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ta, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok || !l.trusted(ta.AddrPort().Addr().Unmap()) {
			return c, nil
		}
		return &proxyConn{Conn: c}, nil // the header is read lazily: Accept must not block on a slow peer
	}
}

func (l *ProxyListener) trusted(a netip.Addr) bool {
	for _, p := range l.Trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type proxyConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
	err    error
	once   sync.Once
}

func (c *proxyConn) header() { c.once.Do(c.readHeader) }

func (c *proxyConn) readHeader() {
	c.r = bufio.NewReader(c.Conn)
	_ = c.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.Conn.SetReadDeadline(time.Time{})
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(c.r, hdr); err != nil || !bytes.Equal(hdr[:12], proxyV2Sig) || hdr[12]>>4 != 2 {
		c.err = errors.New("mux: PROXY protocol v2 header expected from a trusted front")
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[14:]))
	if n > 512 {
		c.err = errors.New("mux: PROXY header too long")
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.r, body); err != nil {
		c.err = err
		return
	}
	if hdr[12]&0x0f != 1 { // LOCAL: health check of the proxy itself
		return
	}
	switch hdr[13] {
	case 0x11:
		if n >= 12 {
			c.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[0:4])), binary.BigEndian.Uint16(body[8:10])))
		}
	case 0x21:
		if n >= 36 {
			c.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[0:16])).Unmap(), binary.BigEndian.Uint16(body[32:34])))
		}
	}
}

func (c *proxyConn) Read(p []byte) (int, error) {
	c.header()
	if c.err != nil {
		return 0, c.err
	}
	return c.r.Read(p)
}

// RemoteAddr is the client's address. net/http asks for it before the first
// read, in the connection's own goroutine, so reading the header here (with
// a deadline) blocks nobody else.
func (c *proxyConn) RemoteAddr() net.Addr {
	c.header()
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}
