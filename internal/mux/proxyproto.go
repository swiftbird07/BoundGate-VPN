package mux

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PROXY protocol (haproxy.org/download/2.9/doc/proxy-protocol.txt): what
// the front, or any TCP reverse proxy in SNI-passthrough mode, puts before
// the client's bytes so the server learns who is calling. The mux, HAProxy
// and Traefik send the binary v2; nginx's stream module can only send the
// text v1 ("PROXY TCP4 src dst sport dport\r\n"). Both are read.

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

// ProxyListener accepts PROXY v1 and v2 headers from trusted sources and
// reports the carried address as RemoteAddr. Connections from anyone else
// pass through unchanged, so a server can be reachable both ways. A trusted
// source may also send no header at all (an HTTP reverse proxy that
// re-encrypts to the admin name cannot send one): the connection then
// starts with a TLS record, which no PROXY header can be mistaken for, and
// RemoteAddr stays the proxy's own address.
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

	dmu    sync.Mutex
	readDL time.Time // the read deadline the user of the connection set
}

// SetReadDeadline and SetDeadline remember the user's read deadline: the
// header is read lazily, inside the user's first Read, and must leave that
// deadline in place afterwards (a peek for the ClientHello has one).
func (c *proxyConn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	c.readDL = t
	c.dmu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *proxyConn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	c.readDL = t
	c.dmu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *proxyConn) header() { c.once.Do(c.readHeader) }

func (c *proxyConn) readHeader() {
	c.r = bufio.NewReader(c.Conn)
	c.dmu.Lock()
	user := c.readDL
	c.dmu.Unlock()
	dl := time.Now().Add(10 * time.Second)
	if !user.IsZero() && user.Before(dl) {
		dl = user
	}
	_ = c.Conn.SetReadDeadline(dl)
	defer c.Conn.SetReadDeadline(user)
	first, err := c.r.Peek(6)
	if err != nil {
		c.err = err
		return
	}
	if bytes.Equal(first, []byte("PROXY ")) {
		c.readV1()
		return
	}
	if !bytes.Equal(first, proxyV2Sig[:6]) {
		return // no header: a TLS ClientHello (0x16 ...) straight from a trusted HTTP proxy
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(c.r, hdr); err != nil || !bytes.Equal(hdr[:12], proxyV2Sig) || hdr[12]>>4 != 2 {
		c.err = errors.New("mux: malformed PROXY protocol v2 header from a trusted front")
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

// readV1 parses the text header: "PROXY TCP4|TCP6 src dst sport dport\r\n"
// or "PROXY UNKNOWN ...\r\n", at most 107 bytes.
func (c *proxyConn) readV1() {
	var line []byte
	for len(line) < 107 {
		b, err := c.r.ReadByte()
		if err != nil {
			c.err = err
			return
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		c.err = errors.New("mux: malformed PROXY protocol v1 header from a trusted front")
		return
	}
	f := strings.Fields(string(line))
	if len(f) < 2 || f[1] == "UNKNOWN" {
		return
	}
	if len(f) != 6 || (f[1] != "TCP4" && f[1] != "TCP6") {
		c.err = errors.New("mux: malformed PROXY protocol v1 header from a trusted front")
		return
	}
	ip, err1 := netip.ParseAddr(f[2])
	port, err2 := strconv.ParseUint(f[4], 10, 16)
	if err1 != nil || err2 != nil {
		c.err = errors.New("mux: malformed PROXY protocol v1 address from a trusted front")
		return
	}
	c.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(port)))
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
// CloseWrite half-closes the connection, so the mux can relay an EOF.
func (c *proxyConn) CloseWrite() error {
	if t, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return t.CloseWrite()
	}
	return nil
}

func (c *proxyConn) RemoteAddr() net.Addr {
	c.header()
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}
