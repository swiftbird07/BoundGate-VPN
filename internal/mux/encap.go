// Package mux lets several BoundGate servers share one public address and
// port: a front process owns :443 (TCP and UDP) and routes by TLS server
// name without terminating TLS. Control plane and hub keep their own keys
// and their own mTLS; the front holds no secret at all.
//
// UDP: QUIC connections are routed by the server name in the client's
// Initial packet and afterwards by the first byte of the destination
// connection ID, which every backend sets to its id (CIDGenerator). Between
// front and backend each datagram travels with a small header that carries
// the client's address, so the backend sees real peers (address validation,
// connection migration, rate limits, logs keep working) and the front needs
// no per-connection state for the way back.
//
// TCP: the ClientHello is peeked, the connection is spliced to the backend,
// optionally behind a PROXY protocol v2 header.
package mux

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// CIDLen is the length of every connection ID issued behind a mux. Short
// header packets do not say how long their connection ID is, so it is fixed.
const CIDLen = 8

// CIDGenerator issues connection IDs whose first byte is the backend id.
type CIDGenerator struct{ ID byte }

// GenerateConnectionID implements quic.ConnectionIDGenerator.
func (g CIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, CIDLen)
	if _, err := rand.Read(b[1:]); err != nil {
		return quic.ConnectionID{}, err
	}
	b[0] = g.ID
	return quic.ConnectionIDFromBytes(b), nil
}

// ConnectionIDLen implements quic.ConnectionIDGenerator.
func (g CIDGenerator) ConnectionIDLen() int { return CIDLen }

// Encapsulation header between front and backend, both directions:
//
//	magic 'B','G'  version 1  family 4|6  address (16 bytes, v4 mapped)  port (2)
const (
	encapLen   = 22
	encapMagic = "BG\x01"
)

func putEncap(dst []byte, client netip.AddrPort) {
	copy(dst, encapMagic)
	a := client.Addr()
	if a.Is4() || a.Is4In6() {
		dst[3] = 4
	} else {
		dst[3] = 6
	}
	b := a.As16()
	copy(dst[4:20], b[:])
	dst[20], dst[21] = byte(client.Port()>>8), byte(client.Port())
}

func getEncap(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < encapLen || string(b[:3]) != encapMagic || (b[3] != 4 && b[3] != 6) {
		return netip.AddrPort{}, nil, errors.New("mux: not an encapsulated datagram")
	}
	var a16 [16]byte
	copy(a16[:], b[4:20])
	a := netip.AddrFrom16(a16)
	if b[3] == 4 {
		a = a.Unmap()
	}
	return netip.AddrPortFrom(a, uint16(b[20])<<8|uint16(b[21])), b[encapLen:], nil
}

// BackendConn is the net.PacketConn a server behind a mux hands to quic-go.
// ReadFrom returns the client's address, not the front's; WriteTo sends
// through the front that delivered that client.
type BackendConn struct {
	pc      net.PacketConn
	trusted []netip.Prefix

	mu    sync.RWMutex
	front net.Addr // where the last valid datagram came from
}

// ListenBackend binds addr for a server behind a mux. Only datagrams from
// trusted sources are accepted: the header is not authenticated, so whoever
// can reach this socket can claim any client address. Bind it to loopback
// or a private network.
func ListenBackend(addr string, trusted []netip.Prefix) (*BackendConn, error) {
	if len(trusted) == 0 {
		return nil, errors.New("mux: a server behind a mux needs the addresses of its front (trusted)")
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("mux: listen %s: %w", addr, err)
	}
	return &BackendConn{pc: pc, trusted: trusted}, nil
}

func (c *BackendConn) isTrusted(a net.Addr) bool {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, p := range c.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ReadFrom implements net.PacketConn.
func (c *BackendConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+encapLen)
	for {
		n, from, err := c.pc.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if !c.isTrusted(from) {
			continue
		}
		client, payload, err := getEncap(buf[:n])
		if err != nil {
			continue
		}
		c.mu.Lock()
		c.front = from
		c.mu.Unlock()
		return copy(p, payload), net.UDPAddrFromAddrPort(client), nil
	}
}

// WriteTo implements net.PacketConn.
func (c *BackendConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("mux: not a UDP address")
	}
	c.mu.RLock()
	front := c.front
	c.mu.RUnlock()
	if front == nil {
		return 0, errors.New("mux: no front has delivered anything yet")
	}
	buf := make([]byte, encapLen+len(p))
	putEncap(buf, ua.AddrPort())
	copy(buf[encapLen:], p)
	if _, err := c.pc.WriteTo(buf, front); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.PacketConn.
func (c *BackendConn) Close() error { return c.pc.Close() }

// LocalAddr implements net.PacketConn.
func (c *BackendConn) LocalAddr() net.Addr { return c.pc.LocalAddr() }

// SetDeadline implements net.PacketConn.
func (c *BackendConn) SetDeadline(t time.Time) error { return c.pc.SetDeadline(t) }

// SetReadDeadline implements net.PacketConn.
func (c *BackendConn) SetReadDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }

// SetWriteDeadline implements net.PacketConn.
func (c *BackendConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

// ParseTrusted parses addresses or prefixes ("127.0.0.1", "172.18.0.0/16").
func ParseTrusted(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("mux: trusted %q is neither an address nor a prefix", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
