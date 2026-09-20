package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// The relay lets two nodes that cannot reach each other directly run the
// tunnel handshake with each other through a hub. The hub only moves UDP
// payloads between two request streams of nodes it authenticated; what is
// inside is the QUIC connection of the two nodes, with its own mTLS against
// the pinned device keys, so the hub sees ciphertext and cannot take part.
//
// On the wire the dialing side is CONNECT-UDP (RFC 9298): extended CONNECT,
// ":protocol" connect-udp, the target in the path, HTTP datagrams with
// context ID 0. The target is an overlay address, not a socket: the hub never
// opens a UDP socket for anyone, it hands the payload to the node that
// listens for that address. The listening side follows the shape of
// draft-ietf-masque-connect-udp-listen (header "connect-udp-bind", datagrams
// that carry the other side's address) with a fixed context ID instead of
// the draft's negotiation; both ends are BoundGate nodes, interoperability
// with other listeners is not claimed.
const (
	relayProtocol   = "connect-udp"
	relayPathPrefix = "/.well-known/masque/udp/"
	relayBindHeader = "Connect-Udp-Bind"
	// RelayPort is the one virtual port every node listens on.
	RelayPort = 443

	ctxDial   = 0x00 // RFC 9298: UDP payload follows
	ctxListen = 0x02 // IPv4 address, port, UDP payload follow

	relayMaxDialers = 64 // per listener
	// RelayPathMTU is the largest IP packet that fits a tunnel run through
	// a relay: the inner QUIC connection stays at 1200 byte packets, because
	// that is all the outer connection's datagrams are certain to carry.
	RelayPathMTU = 1100
)

// RelayHandler is implemented by a Handler that also relays. Both methods
// get a peer this package authenticated and answer with an HTTP status.
type RelayHandler interface {
	// RelayListen: may peer receive what is sent to addr? Only its own
	// overlay address is a sensible yes.
	RelayListen(peer AuthenticatedPeer, addr netip.Addr) int
	// RelayDial: may peer send to the node listening at target? src is the
	// address the listener is told the traffic comes from (the dialer's
	// overlay address).
	RelayDial(peer AuthenticatedPeer, target netip.Addr) (src netip.Addr, status int)
}

// RelayStats counts what a server relayed since it started.
type RelayStats struct {
	Listeners int    `json:"listeners"`
	Dialers   int    `json:"dialers"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}

type relay struct {
	mu        sync.Mutex
	listeners map[netip.Addr]*relayListener
	packets   atomic.Uint64
	bytes     atomic.Uint64
}

type relayListener struct {
	owner   DeviceID
	str     *http3.Stream
	cancel  context.CancelFunc
	dialers map[uint16]*relayDialer
	next    uint16
}

type relayDialer struct {
	src    netip.AddrPort
	str    *http3.Stream
	cancel context.CancelFunc
}

func parseRelayPath(p string) (netip.Addr, error) {
	rest, ok := strings.CutPrefix(p, relayPathPrefix)
	if !ok {
		return netip.Addr{}, errors.New("not a connect-udp path")
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 || parts[1] != fmt.Sprint(RelayPort) {
		return netip.Addr{}, errors.New("target must be <overlay address>/443")
	}
	a, err := netip.ParseAddr(parts[0])
	if err != nil || !a.Is4() {
		return netip.Addr{}, errors.New("target must be an IPv4 overlay address")
	}
	return a, nil
}

// RelayAddr is the address of the node listening for a, as the PacketConn of
// RelayDial understands it (ClientConfig.Remote).
func RelayAddr(a netip.Addr) net.Addr { return &net.UDPAddr{IP: a.AsSlice(), Port: RelayPort} }

func relayPath(a netip.Addr) string { return fmt.Sprintf("%s%s/%d/", relayPathPrefix, a, RelayPort) }

// RelayStats reports the relay's counters.
func (s *Server) RelayStats() RelayStats {
	s.relay.mu.Lock()
	defer s.relay.mu.Unlock()
	st := RelayStats{Listeners: len(s.relay.listeners), Packets: s.relay.packets.Load(), Bytes: s.relay.bytes.Load()}
	for _, l := range s.relay.listeners {
		st.Dialers += len(l.dialers)
	}
	return st
}

// handleRelay serves one connect-udp request of an authenticated peer.
func (s *Server) handleRelay(w http.ResponseWriter, r *http.Request, peer AuthenticatedPeer) {
	rh, ok := s.h.(RelayHandler)
	if !ok {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	target, err := parseRelayPath(r.URL.Path)
	if err != nil {
		s.log.Warn("transport: bad relay request", "peer", peer, "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if r.Header.Get(relayBindHeader) == "?1" {
		if st := rh.RelayListen(peer, target); st != http.StatusOK {
			w.WriteHeader(st)
			return
		}
		s.relayListen(ctx, cancel, w, peer, target)
		return
	}
	src, st := rh.RelayDial(peer, target)
	if st != http.StatusOK {
		w.WriteHeader(st)
		return
	}
	s.relayDial(ctx, cancel, w, peer, src, target)
}

func takeOver(w http.ResponseWriter) *http3.Stream {
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	return w.(http3.HTTPStreamer).HTTPStream()
}

// untilClosed cancels when the peer ends the request stream; nothing but
// capsules we do not use can arrive on it.
func untilClosed(str *http3.Stream, cancel context.CancelFunc) {
	_, _ = io.Copy(io.Discard, str)
	cancel()
}

func (s *Server) relayListen(ctx context.Context, cancel context.CancelFunc, w http.ResponseWriter, peer AuthenticatedPeer, addr netip.Addr) {
	str := takeOver(w)
	defer str.Close()
	l := &relayListener{owner: peer.DeviceID(), str: str, cancel: cancel, dialers: make(map[uint16]*relayDialer), next: 1024}
	s.relay.mu.Lock()
	if old := s.relay.listeners[addr]; old != nil {
		old.cancel() // the node reconnected; its old stream may not have noticed yet
	}
	s.relay.listeners[addr] = l
	s.relay.mu.Unlock()
	s.log.Info("transport: relay listener", "peer", peer, "addr", addr)
	defer func() {
		s.relay.mu.Lock()
		if s.relay.listeners[addr] == l {
			delete(s.relay.listeners, addr)
		}
		for _, d := range l.dialers {
			d.cancel()
		}
		s.relay.mu.Unlock()
		s.log.Info("transport: relay listener gone", "peer", peer, "addr", addr)
	}()
	go untilClosed(str, cancel)
	for {
		b, err := str.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(b) < 7 || b[0] != ctxListen {
			continue
		}
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[1:5])), binary.BigEndian.Uint16(b[5:7]))
		s.relay.mu.Lock()
		d := l.dialers[dst.Port()]
		s.relay.mu.Unlock()
		if d == nil || d.src != dst {
			continue
		}
		b[6] = ctxDial // reuse the buffer: context ID 0 in front of the payload
		if d.str.SendDatagram(b[6:]) == nil {
			s.relay.packets.Add(1)
			s.relay.bytes.Add(uint64(len(b) - 7))
		}
	}
}

func (s *Server) relayDial(ctx context.Context, cancel context.CancelFunc, w http.ResponseWriter, peer AuthenticatedPeer, src, target netip.Addr) {
	s.relay.mu.Lock()
	l := s.relay.listeners[target]
	full := l != nil && len(l.dialers) >= relayMaxDialers
	s.relay.mu.Unlock()
	if l == nil {
		w.WriteHeader(http.StatusNotFound) // the target does not listen here
		return
	}
	if full {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	// the listener must not learn of the dialer before its stream exists
	d := &relayDialer{str: takeOver(w), cancel: cancel}
	s.relay.mu.Lock()
	if s.relay.listeners[target] != l {
		s.relay.mu.Unlock()
		_ = d.str.Close() // the listener left in between
		return
	}
	for l.dialers[l.next] != nil || l.next < 1024 {
		l.next++
	}
	d.src = netip.AddrPortFrom(src, l.next)
	l.next++
	l.dialers[d.src.Port()] = d
	s.relay.mu.Unlock()
	remove := func() {
		s.relay.mu.Lock()
		if l.dialers[d.src.Port()] == d {
			delete(l.dialers, d.src.Port())
		}
		s.relay.mu.Unlock()
	}
	defer d.str.Close()
	defer remove()
	s.log.Info("transport: relay pair", "dialer", peer, "as", d.src, "target", target, "listener", l.owner)
	start := time.Now()
	defer func() {
		s.log.Info("transport: relay pair closed", "dialer", peer, "target", target, "duration", time.Since(start).Round(time.Millisecond).String())
	}()
	go untilClosed(d.str, cancel)
	head := make([]byte, 7)
	head[0] = ctxListen
	a := src.As4()
	copy(head[1:5], a[:])
	binary.BigEndian.PutUint16(head[5:7], d.src.Port())
	for {
		b, err := d.str.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(b) < 1 || b[0] != ctxDial {
			continue
		}
		out := make([]byte, 0, 6+len(b))
		out = append(append(out, head...), b[1:]...)
		if l.str.SendDatagram(out) == nil {
			s.relay.packets.Add(1)
			s.relay.bytes.Add(uint64(len(b) - 1))
		}
	}
}

// ---- the nodes' side ----

// ErrNoRelay: the link cannot carry relay streams (TCP fallback).
var ErrNoRelay = errors.New("transport: this hub connection cannot relay (not QUIC)")

// RelayError is a hub's refusal of a relay request.
type RelayError struct{ Status int }

func (e *RelayError) Error() string {
	switch e.Status {
	case http.StatusNotFound:
		return "transport: the peer does not listen at this hub"
	case http.StatusNotImplemented:
		return "transport: this hub does not relay"
	}
	return fmt.Sprintf("transport: hub refused the relay request with HTTP %d", e.Status)
}

// RelayListen asks the hub of this tunnel to deliver what other nodes send
// to self. The returned PacketConn is what the node's own tunnel server
// listens on (ServerConfig.PacketConn with Relayed).
func (t *ClientTunnel) RelayListen(ctx context.Context, self netip.Addr) (net.PacketConn, error) {
	return t.openRelay(ctx, self, self, true)
}

// RelayDial opens a path to the node listening for target. The returned
// PacketConn carries one QUIC connection to it (ClientConfig.PacketConn).
func (t *ClientTunnel) RelayDial(ctx context.Context, self, target netip.Addr) (net.PacketConn, error) {
	return t.openRelay(ctx, self, target, false)
}

func (t *ClientTunnel) openRelay(ctx context.Context, self, target netip.Addr, listen bool) (net.PacketConn, error) {
	ql, ok := t.link.(*quicClientLink)
	if !ok {
		return nil, ErrNoRelay
	}
	str, err := ql.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("transport: relay stream: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+HubServerName+relayPath(target), nil)
	if err != nil {
		return nil, err
	}
	req.Proto = relayProtocol
	req.Header.Set("Capsule-Protocol", "?1")
	if listen {
		req.Header.Set(relayBindHeader, "?1")
	}
	if err := str.SendRequestHeader(req); err != nil {
		return nil, fmt.Errorf("transport: relay request: %w", err)
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		return nil, fmt.Errorf("transport: relay response: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		_ = str.Close()
		return nil, &RelayError{Status: rsp.StatusCode}
	}
	c := &relayConn{str: str, listen: listen, local: &net.UDPAddr{IP: self.AsSlice(), Port: RelayPort}, peer: &net.UDPAddr{IP: target.AsSlice(), Port: RelayPort},
		in: make(chan relayPacket, 256), closed: make(chan struct{}), deadline: newDeadline()}
	go c.receive()
	go func() {
		// the hub ends the stream when the other side left or this node lost
		// its admission; only a reader learns of that
		_, _ = io.Copy(io.Discard, str)
		_ = c.Close()
	}()
	return c, nil
}

type relayPacket struct {
	b    []byte
	from *net.UDPAddr
}

// relayConn is the net.PacketConn a QUIC transport runs on: datagrams of one
// relay stream, addressed with overlay addresses.
type relayConn struct {
	str    *http3.RequestStream
	listen bool
	local  *net.UDPAddr
	peer   *net.UDPAddr // dialing side: the one remote
	in     chan relayPacket
	once   sync.Once
	closed chan struct{}

	dmu      sync.Mutex
	deadline *deadline
	until    time.Time
}

// deadline is closed when a read deadline passes. A blocked ReadFrom waits on
// the one it saw, so a deadline in the past closes that one in place.
type deadline struct {
	ch   chan struct{}
	once sync.Once
}

func newDeadline() *deadline { return &deadline{ch: make(chan struct{})} }
func (d *deadline) pass()    { d.once.Do(func() { close(d.ch) }) }
func (d *deadline) passed() bool {
	select {
	case <-d.ch:
		return true
	default:
		return false
	}
}

func (c *relayConn) receive() {
	defer c.Close()
	for {
		b, err := c.str.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		p := relayPacket{from: c.peer}
		switch {
		case !c.listen && len(b) >= 1 && b[0] == ctxDial:
			p.b = b[1:]
		case c.listen && len(b) >= 7 && b[0] == ctxListen:
			p.b, p.from = b[7:], &net.UDPAddr{IP: net.IP(b[1:5]), Port: int(binary.BigEndian.Uint16(b[5:7]))}
		default:
			continue
		}
		select {
		case c.in <- p:
		case <-c.closed:
			return
		default: // a full queue drops, like a socket buffer
		}
	}
}

func (c *relayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.dmu.Lock()
	dl := c.deadline.ch
	c.dmu.Unlock()
	select {
	case pkt := <-c.in:
		return copy(p, pkt.b), pkt.from, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-dl:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *relayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	var b []byte
	if c.listen {
		ua, ok := addr.(*net.UDPAddr)
		ip := ua.IP.To4()
		if !ok || ip == nil {
			return 0, fmt.Errorf("transport: relay address %v", addr)
		}
		b = make([]byte, 7, 7+len(p))
		b[0] = ctxListen
		copy(b[1:5], ip)
		binary.BigEndian.PutUint16(b[5:7], uint16(ua.Port))
	} else {
		b = make([]byte, 1, 1+len(p))
	}
	// too large for the hub connection right now: lost, as on any path
	_ = c.str.SendDatagram(append(b, p...))
	return len(p), nil
}

func (c *relayConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.str.CancelRead(0)
		_ = c.str.Close()
	})
	return nil
}

// Done is closed when the relay stream ended: the hub closed it (the other
// side left, this node lost its admission) or the hub connection is gone.
func (c *relayConn) Done() <-chan struct{} { return c.closed }

func (c *relayConn) LocalAddr() net.Addr { return c.local }

func (c *relayConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *relayConn) SetWriteDeadline(time.Time) error { return nil }

func (c *relayConn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if !t.IsZero() && !t.After(time.Now()) {
		c.deadline.pass() // wakes a blocked ReadFrom
		return nil
	}
	if c.deadline.passed() {
		c.deadline = newDeadline()
	}
	if !t.IsZero() {
		d := c.deadline
		time.AfterFunc(time.Until(t), func() {
			c.dmu.Lock()
			current := c.deadline == d && c.until.Equal(t)
			c.dmu.Unlock()
			if current {
				d.pass()
			}
		})
	}
	c.until = t
	return nil
}
