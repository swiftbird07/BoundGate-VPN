package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Route sends the listed server names to one backend.
type Route struct {
	Name string   // for logs
	SNI  []string // exact names; "*.example.com" matches one label
	// ID is the first byte of the backend's QUIC connection IDs (behind_mux.id
	// of that server). Required with UDP.
	ID  byte
	UDP string // backend address for QUIC ("" = none)
	TCP string // backend address for TLS ("" = none)
	// ProxyProtocol sends a PROXY protocol v2 header on TCP so the backend
	// learns the client address.
	ProxyProtocol bool
}

// Config of the front.
type Config struct {
	Listen string // ":443", TCP and UDP
	Routes []Route
	// DefaultTCP receives TLS connections for every other name, untouched:
	// the web server or reverse proxy that would otherwise own port 443.
	DefaultTCP string
	// DefaultProxyProtocol sends a PROXY v2 header to DefaultTCP as well, so
	// a web server or reverse proxy there sees real client addresses.
	DefaultProxyProtocol bool
	// NoTCP: only UDP is served here; TCP/443 belongs to a reverse proxy that
	// passes the BoundGate names through by SNI.
	NoTCP bool
	Log   *slog.Logger
}

// Front is the running mux.
type Front struct {
	cfg    Config
	log    *slog.Logger
	udp    *net.UDPConn
	tcp    net.Listener
	byID   map[byte]*backend
	byName map[string]*backend
	wild   map[string]*backend // suffix after "*"

	mu      sync.Mutex
	initial map[flowKey]*flow
}

type backend struct {
	route Route
	conn  *net.UDPConn // connected to route.UDP
}

// flowKey identifies a handshake in flight: before the server has issued a
// connection ID, the client's address and its random DCID are all there is.
type flowKey struct {
	client netip.AddrPort
	dcid   string
}

type flow struct {
	be      *backend
	crypto  cryptoBuf
	held    [][]byte // datagrams waiting for the name
	expires time.Time
}

const (
	flowTTL     = 15 * time.Second
	maxFlows    = 8192
	maxHeld     = 4
	tcpPeekMax  = 16 * 1024
	tcpPeekWait = 10 * time.Second
)

// New validates the configuration and binds the sockets.
func New(cfg Config) (*Front, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	f := &Front{cfg: cfg, log: cfg.Log, byID: map[byte]*backend{}, byName: map[string]*backend{}, wild: map[string]*backend{}, initial: map[flowKey]*flow{}}
	for _, r := range cfg.Routes {
		be := &backend{route: r}
		if r.UDP == "" && r.TCP == "" {
			return nil, fmt.Errorf("mux: route %q has no backend", r.Name)
		}
		if r.UDP != "" {
			if _, dup := f.byID[r.ID]; dup {
				return nil, fmt.Errorf("mux: route %q: id %d is used twice", r.Name, r.ID)
			}
			ua, err := net.ResolveUDPAddr("udp", r.UDP)
			if err != nil {
				return nil, fmt.Errorf("mux: route %q: %w", r.Name, err)
			}
			if be.conn, err = net.DialUDP("udp", nil, ua); err != nil {
				return nil, fmt.Errorf("mux: route %q: %w", r.Name, err)
			}
			f.byID[r.ID] = be
		}
		if len(r.SNI) == 0 {
			return nil, fmt.Errorf("mux: route %q has no server names", r.Name)
		}
		for _, n := range r.SNI {
			n = strings.ToLower(strings.TrimSpace(n))
			if rest, ok := strings.CutPrefix(n, "*"); ok && strings.HasPrefix(rest, ".") {
				f.wild[rest] = be
			} else if _, dup := f.byName[n]; dup {
				return nil, fmt.Errorf("mux: server name %q is routed twice", n)
			} else {
				f.byName[n] = be
			}
		}
	}
	ua, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	if f.udp, err = net.ListenUDP("udp", ua); err != nil {
		return nil, fmt.Errorf("mux: %w", err)
	}
	_ = f.udp.SetReadBuffer(7 << 20)
	_ = f.udp.SetWriteBuffer(7 << 20)
	if cfg.NoTCP {
		return f, nil
	}
	if f.tcp, err = net.Listen("tcp", cfg.Listen); err != nil {
		f.udp.Close()
		return nil, fmt.Errorf("mux: %w", err)
	}
	return f, nil
}

// UDPAddr and TCPAddr return the bound addresses (tests listen on port 0).
func (f *Front) UDPAddr() net.Addr { return f.udp.LocalAddr() }
func (f *Front) TCPAddr() net.Addr {
	if f.tcp == nil {
		return nil
	}
	return f.tcp.Addr()
}

func (f *Front) lookup(name string) *backend {
	if be := f.byName[name]; be != nil {
		return be
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		return f.wild[name[i:]]
	}
	return nil
}

// Run serves until ctx ends.
func (f *Front) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, be := range f.byID {
		wg.Add(1)
		go func(be *backend) { defer wg.Done(); f.fromBackend(be) }(be)
	}
	wg.Add(1)
	go func() { defer wg.Done(); f.fromClients() }()
	if f.tcp != nil {
		wg.Add(1)
		go func() { defer wg.Done(); f.acceptTCP(ctx) }()
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				f.mu.Lock()
				for k, fl := range f.initial {
					if now.After(fl.expires) {
						delete(f.initial, k)
					}
				}
				f.mu.Unlock()
			}
		}
	}()
	for _, r := range f.cfg.Routes {
		f.log.Info("route", "name", r.Name, "sni", r.SNI, "id", r.ID, "udp", r.UDP, "tcp", r.TCP)
	}
	f.log.Info("mux listening", "addr", f.cfg.Listen, "default_tcp", f.cfg.DefaultTCP)
	<-ctx.Done()
	f.udp.Close()
	if f.tcp != nil {
		f.tcp.Close()
	}
	for _, be := range f.byID {
		be.conn.Close()
	}
	wg.Wait()
	return nil
}

// --- UDP ---

func (f *Front) fromClients() {
	buf := make([]byte, encapLen+65535)
	for {
		n, client, err := f.udp.ReadFromUDPAddrPort(buf[encapLen:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		pkt := buf[encapLen : encapLen+n]
		be, held := f.routeUDP(client, pkt)
		if be == nil {
			continue
		}
		for _, h := range held { // earlier datagrams of this handshake, in order
			f.toBackend(be, client, h, nil)
		}
		f.toBackend(be, client, pkt, buf[:encapLen+n])
	}
}

// toBackend sends pkt with the client's address in front. frame, when given,
// is pkt with encapLen free bytes before it (no copy).
func (f *Front) toBackend(be *backend, client netip.AddrPort, pkt, frame []byte) {
	if frame == nil {
		frame = make([]byte, encapLen+len(pkt))
		copy(frame[encapLen:], pkt)
	}
	putEncap(frame, client)
	_, _ = be.conn.Write(frame)
}

// routeUDP decides where a datagram goes. held are datagrams that waited
// for this decision.
func (f *Front) routeUDP(client netip.AddrPort, pkt []byte) (*backend, [][]byte) {
	if len(pkt) < 1+CIDLen {
		return nil, nil
	}
	if pkt[0]&0x80 == 0 { // short header: the connection ID is one of ours
		return f.byID[pkt[1]], nil
	}
	h, err := parseLongHeader(pkt)
	if err != nil {
		return nil, nil
	}
	if h.version != quicV1 && h.version != quicV2 {
		return f.first(), nil // unknown version: let a real QUIC server answer with version negotiation
	}
	key := flowKey{client, string(h.dcid)}
	f.mu.Lock()
	defer f.mu.Unlock()
	fl := f.initial[key]
	if fl != nil && fl.be != nil {
		fl.expires = time.Now().Add(flowTTL)
		return fl.be, nil
	}
	if !h.initial {
		// Handshake and later: the DCID was issued by a backend
		if len(h.dcid) == CIDLen {
			return f.byID[h.dcid[0]], nil
		}
		return nil, nil
	}
	payload, err := openInitial(pkt, h)
	if err != nil {
		// not the client's first DCID: a later Initial, addressed to a backend's connection ID
		if len(h.dcid) == CIDLen {
			return f.byID[h.dcid[0]], nil
		}
		return nil, nil
	}
	if fl == nil {
		if len(f.initial) >= maxFlows {
			return nil, nil // under flood: clients retry, established connections are unaffected
		}
		fl = &flow{}
		f.initial[key] = fl
	}
	fl.expires = time.Now().Add(flowTTL)
	_ = cryptoFrames(payload, &fl.crypto)
	name, err := clientHelloSNI(fl.crypto.prefix())
	switch {
	case err == nil:
		be := f.lookup(name)
		if be == nil || be.conn == nil {
			f.log.Debug("no QUIC route", "sni", name, "client", client)
			delete(f.initial, key)
			return nil, nil
		}
		fl.be = be
		held := fl.held
		fl.held, fl.crypto = nil, cryptoBuf{}
		return be, held
	case errors.Is(err, errNeedMore) && len(fl.held) < maxHeld:
		fl.held = append(fl.held, append([]byte(nil), pkt...))
		return nil, nil
	default:
		delete(f.initial, key)
		return nil, nil
	}
}

func (f *Front) first() *backend {
	for _, r := range f.cfg.Routes {
		if r.UDP != "" {
			return f.byID[r.ID]
		}
	}
	return nil
}

func (f *Front) fromBackend(be *backend) {
	buf := make([]byte, encapLen+65535)
	for {
		n, err := be.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // ICMP unreachable while the backend restarts
			continue
		}
		client, payload, err := getEncap(buf[:n])
		if err != nil {
			continue
		}
		_, _ = f.udp.WriteToUDPAddrPort(payload, client)
	}
}

// --- TCP ---

func (f *Front) acceptTCP(ctx context.Context) {
	for {
		c, err := f.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go f.serveTCP(c)
	}
}

func (f *Front) serveTCP(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(tcpPeekWait))
	name, raw, err := readTLSClientHello(c, tcpPeekMax)
	_ = c.SetReadDeadline(time.Time{})
	target, proxy := f.cfg.DefaultTCP, f.cfg.DefaultProxyProtocol
	if err == nil {
		if be := f.lookup(name); be != nil && be.route.TCP != "" {
			target, proxy = be.route.TCP, be.route.ProxyProtocol
		}
	}
	if target == "" || len(raw) == 0 {
		return
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		f.log.Warn("backend not reachable", "backend", target, "err", err)
		return
	}
	defer up.Close()
	if proxy {
		if _, err := up.Write(ProxyV2Header(c.RemoteAddr(), c.LocalAddr())); err != nil {
			return
		}
	}
	if _, err := up.Write(raw); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.CloseWrite()
	}
}
