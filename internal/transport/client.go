package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// ClientConfig configures the agent side of a tunnel.
type ClientConfig struct {
	// GatewayAddr is host:port of the gateway's UDP listener.
	GatewayAddr string
	// TLS must come from ClientTLSConfig.
	TLS *tls.Config
	// Template is the gateway's CONNECT-IP URI template.
	Template    string
	IdleTimeout time.Duration
	// KeepAlive is how often a quiet tunnel sends a PING, which keeps the
	// NAT binding and the hub's idle timer alive. Default 20s; negative:
	// never (a phone's radio stays asleep; the tunnel then ends after
	// IdleTimeout without traffic).
	KeepAlive time.Duration
	// HandshakeTimeout bounds the QUIC or TLS handshake. Default 5s: on a
	// network that blacks out UDP this is how long the QUIC attempt takes
	// before the caller falls back to TCP.
	HandshakeTimeout time.Duration
	// PacketConn, when set, carries the connection instead of a UDP socket:
	// a relay stream from ClientTunnel.RelayDial, Remote the node behind it.
	// GatewayAddr is then unused. The connection stays at the minimum packet
	// size (see ServerConfig.Relayed); Dial closes PacketConn with the tunnel.
	PacketConn net.PacketConn
	Remote     net.Addr
}

func (c ClientConfig) withDefaults() ClientConfig {
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 60 * time.Second
	}
	if c.KeepAlive == 0 {
		c.KeepAlive = 20 * time.Second
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 5 * time.Second
	}
	return c
}

// keepAlivePeriod is KeepAlive as quic-go takes it: 0 sends none.
func keepAlivePeriod(d time.Duration) time.Duration {
	return max(d, 0)
}

// clientLink is what a ClientTunnel needs from its transport.
type clientLink interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) (icmp []byte, err error)
	LocalPrefixes(ctx context.Context) ([]netip.Prefix, error)
	Routes(ctx context.Context) ([]connectip.IPRoute, error)
	Done() <-chan struct{}
	Err() error
	Close(code quic.ApplicationErrorCode, reason string) error
}

// quicClientLink adapts connect-ip-go's client session to clientLink.
type quicClientLink struct {
	conn  *connectip.Conn
	qconn *quic.Conn
	cc    *http3.ClientConn
	tr    *http3.Transport
	relay bool // over a relay stream: the socket is not ours to replace

	// The QUIC transports the connection ran on, oldest first, with their
	// sockets. Closing a transport destroys the connections on it, so every
	// one stays until the link ends (RFC 9000 §9: the peer may still send
	// to the old address until it has validated the new one).
	mu  sync.Mutex
	qts []*quic.Transport
	pcs []net.PacketConn
}

func (l *quicClientLink) ReadPacket(b []byte) (int, error) { return l.conn.ReadPacket(b) }
func (l *quicClientLink) WritePacket(b []byte) ([]byte, error) {
	icmp, err := l.conn.WritePacket(b)
	return tooLarge(b, icmp), err
}
func (l *quicClientLink) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return l.conn.LocalPrefixes(ctx)
}
func (l *quicClientLink) Routes(ctx context.Context) ([]connectip.IPRoute, error) {
	return l.conn.Routes(ctx)
}
func (l *quicClientLink) Done() <-chan struct{} { return l.qconn.Context().Done() }
func (l *quicClientLink) Err() error {
	select {
	case <-l.qconn.Context().Done():
		return context.Cause(l.qconn.Context())
	default:
		return nil
	}
}
func (l *quicClientLink) Close(code quic.ApplicationErrorCode, reason string) error {
	_ = l.conn.Close()
	err := l.qconn.CloseWithError(code, reason)
	_ = l.tr.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.qts {
		_ = l.qts[i].Close()
		_ = l.pcs[i].Close()
	}
	l.qts, l.pcs = nil, nil
	return err
}

// maxMigrations bounds the sockets a link keeps (one per migration). A link
// that moved more often ends and is dialed again instead.
const maxMigrations = 8

// ErrNoMigration: this tunnel cannot move to another socket (it runs over
// a relay stream or over TCP, or has moved too often); close and dial again.
var ErrNoMigration = errors.New("transport: the tunnel cannot migrate")

func (l *quicClientLink) migrate(ctx context.Context) error {
	if l.relay {
		return ErrNoMigration
	}
	l.mu.Lock()
	n := len(l.qts)
	l.mu.Unlock()
	if n > maxMigrations {
		return ErrNoMigration
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	nt := &quic.Transport{Conn: pc}
	p, err := l.qconn.AddPath(nt)
	if err != nil {
		_ = pc.Close()
		return err
	}
	// From here the connection is registered on nt: closing nt would end
	// it, so nt stays with the link whatever happens to the path.
	l.mu.Lock()
	l.qts, l.pcs = append(l.qts, nt), append(l.pcs, pc)
	l.mu.Unlock()
	if err := p.Probe(ctx); err != nil {
		_ = p.Close()
		return err
	}
	if err := p.Switch(); err != nil {
		_ = p.Close()
		return err
	}
	return nil
}

// ClientTunnel is the agent's end of an accepted tunnel.
type ClientTunnel struct {
	link      clientLink
	transport string // "quic" or "tcp"
	dns       []netip.Addr
	cfg       ClientConfig // how this hub was dialed; a relay over TCP dials again

	bytesIn, bytesOut, packetsIn, packetsOut atomic.Uint64

	// Liveness on demand (no keep-alives needed): a tunnel that has taken
	// silentWrites packets over silentFor without one packet coming back
	// is suspect (a NAT binding that vanished, a hub that restarted without
	// a stateless reset key, a socket left on a network that is gone) even
	// if QUIC has not given up on it yet; see recover.
	//
	// quietSince is when the writes without an answer began (0: none),
	// quietWrites how many packets went out since. Both are reset by any
	// packet that arrives. given: a recovery is under way.
	quietSince  atomic.Int64
	quietWrites atomic.Int64
	given       atomic.Bool
}

// After silentFor of sending at least silentWrites packets into a tunnel
// without an answer the tunnel counts as dead. 30 s is above the retransmit
// timers of TCP connections inside the tunnel, so a stall shows as a burst
// of retransmissions before the tunnel is given up on.
var (
	silentFor    = 30 * time.Second
	silentWrites = int64(10)
)

// TunnelStats counts the IP packets a tunnel carried, seen from this end.
type TunnelStats struct {
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
}

// Stats returns what the tunnel carried so far.
func (t *ClientTunnel) Stats() TunnelStats {
	return TunnelStats{BytesIn: t.bytesIn.Load(), BytesOut: t.bytesOut.Load(), PacketsIn: t.packetsIn.Load(), PacketsOut: t.packetsOut.Load()}
}

// Dial performs the QUIC/mTLS handshake and the CONNECT-IP request. Any
// failure in the handshake (including "device not approved") surfaces here.
func Dial(ctx context.Context, cfg ClientConfig) (*ClientTunnel, error) {
	if cfg.TLS == nil || len(cfg.TLS.Certificates) == 0 {
		return nil, errors.New("transport: ClientConfig.TLS must come from ClientTLSConfig")
	}
	tmpl, err := uritemplate.New(cfg.Template)
	if err != nil {
		return nil, fmt.Errorf("transport: template: %w", err)
	}
	cfg = cfg.withDefaults()
	qcfg := &quic.Config{
		EnableDatagrams:      true,
		MaxIdleTimeout:       cfg.IdleTimeout,
		KeepAlivePeriod:      keepAlivePeriod(cfg.KeepAlive),
		HandshakeIdleTimeout: cfg.HandshakeTimeout,
		InitialPacketSize:    PacketSize, // mtu.go
	}
	var qconn *quic.Conn
	var qt, ownQT *quic.Transport // qt: relayed; ownQT: our own UDP socket
	var ownPC net.PacketConn
	pc := cfg.PacketConn
	name := "quic"
	if pc != nil {
		qcfg.InitialPacketSize, qcfg.DisablePathMTUDiscovery = 1200, true
		qt = &quic.Transport{Conn: pc}
		name = "relay"
		qconn, err = qt.Dial(ctx, cfg.Remote, cfg.TLS, qcfg)
		if err != nil {
			_ = qt.Close()
			_ = pc.Close()
			return nil, fmt.Errorf("transport: dial %s through the relay: %w", cfg.Remote, err)
		}
	} else {
		// our own socket and transport (what quic.DialAddr would make), so
		// that Migrate can move the connection to another socket later
		raddr, err := net.ResolveUDPAddr("udp", cfg.GatewayAddr)
		if err != nil {
			return nil, fmt.Errorf("transport: dial %s: %w", cfg.GatewayAddr, err)
		}
		if ownPC, err = net.ListenUDP("udp", nil); err != nil {
			return nil, fmt.Errorf("transport: dial %s: %w", cfg.GatewayAddr, err)
		}
		ownQT = &quic.Transport{Conn: ownPC}
		if qconn, err = ownQT.Dial(ctx, raddr, cfg.TLS, qcfg); err != nil {
			_ = ownQT.Close()
			_ = ownPC.Close()
			return nil, fmt.Errorf("transport: dial %s: %w", cfg.GatewayAddr, err)
		}
	}
	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(qconn)
	conn, rsp, err := connectip.Dial(ctx, cc, tmpl)
	if err != nil {
		status := 0
		if rsp != nil {
			status = rsp.StatusCode
		}
		_ = qconn.CloseWithError(0, "connect-ip failed")
		if qt != nil {
			_ = qt.Close()
			_ = pc.Close()
		} else {
			_ = ownQT.Close()
			_ = ownPC.Close()
		}
		return nil, &DialError{Status: status, Err: err}
	}
	if d, ok := cfg.PacketConn.(interface{ Done() <-chan struct{} }); ok {
		// a relay stream that ended takes the connection on it along at
		// once; QUIC itself would only notice at its idle timeout
		go func() {
			select {
			case <-d.Done():
				_ = qconn.CloseWithError(0, "relay stream ended")
			case <-qconn.Context().Done():
			}
		}()
	}
	var dns []netip.Addr
	if rsp != nil {
		dns = parseDNSHeader(rsp.Header.Get(DNSHeader))
	}
	link := &quicClientLink{conn: conn, qconn: qconn, cc: cc, tr: tr, relay: qt != nil, qts: []*quic.Transport{qt}, pcs: []net.PacketConn{pc}}
	if qt == nil {
		link.qts, link.pcs = []*quic.Transport{ownQT}, []net.PacketConn{ownPC}
	}
	return &ClientTunnel{link: link, transport: name, dns: dns}, nil
}

// DialError reports a CONNECT-IP refusal. Status is the HTTP status if the
// gateway answered (403 = no session), 0 otherwise.
type DialError struct {
	Status int
	Err    error
}

func (e *DialError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("transport: gateway refused tunnel with HTTP %d: %v", e.Status, e.Err)
	}
	return "transport: " + e.Err.Error()
}

func (e *DialError) Unwrap() error { return e.Err }

// Transport is "quic" or "tcp".
func (t *ClientTunnel) Transport() string { return t.transport }

// DNS returns the resolvers the hub offered with this tunnel (DNSHeader).
func (t *ClientTunnel) DNS() []netip.Addr { return t.dns }

// ReadPacket reads one IP packet from the gateway.
func (t *ClientTunnel) ReadPacket(b []byte) (int, error) {
	n, err := t.link.ReadPacket(b)
	if err == nil {
		t.bytesIn.Add(uint64(n))
		t.packetsIn.Add(1)
		t.quietSince.Store(0)
		t.quietWrites.Store(0)
	}
	return n, err
}

// WritePacket sends one IP packet to the gateway.
func (t *ClientTunnel) WritePacket(b []byte) (icmp []byte, err error) {
	icmp, err = t.link.WritePacket(b)
	if err == nil && icmp == nil { // an ICMP answer means the packet did not fit and was not sent
		t.bytesOut.Add(uint64(len(b)))
		t.packetsOut.Add(1)
		t.noteQuietWrite()
	}
	return icmp, err
}

// noteQuietWrite counts a packet sent while nothing has come back, and gives
// the tunnel up when that has gone on for silentFor with silentWrites sent.
func (t *ClientTunnel) noteQuietWrite() {
	now := time.Now().UnixNano()
	since := t.quietSince.Load()
	if since == 0 {
		if !t.quietSince.CompareAndSwap(0, now) {
			since = t.quietSince.Load()
		} else {
			since = now
		}
	}
	if t.quietWrites.Add(1) < silentWrites || now-since < int64(silentFor) {
		return
	}
	if t.given.CompareAndSwap(false, true) {
		go t.recover()
	}
}

// recover is the answer to a tunnel that swallows packets: a new socket and
// a path probe. The hub answers the probe when it still has the connection
// (the NAT binding of the old socket vanished, or the old socket sits on a
// network that is gone), and the tunnel goes on there without anyone
// noticing. No answer within a few seconds, or a tunnel that cannot move,
// ends the tunnel with ErrCodeNoAnswer; the caller dials again.
//
// A tunnel that only ever carries packets one way (a sender nothing answers)
// is probed every silentFor and, after maxMigrations, dialed again.
func (t *ClientTunnel) recover() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := t.Migrate(ctx); err != nil {
		_ = t.link.Close(ErrCodeNoAnswer, "no answer from the hub: "+err.Error())
		return
	}
	t.quietSince.Store(0)
	t.quietWrites.Store(0)
	t.given.Store(false)
}

// Migrate moves the tunnel's QUIC connection onto a new UDP socket, after
// the device changed networks: the old socket may sit on an interface that
// is gone, or that the system keeps for it while all other traffic moved
// elsewhere (an iPhone keeps a socket on cellular after Wi-Fi came up). The
// hub sees the new address once the path is validated and answers there;
// the tunnel, its address, routes and flows continue. Returns ErrNoMigration
// for tunnels that cannot move (over a relay, over TCP, moved too often):
// close and dial again instead. Any other error means the hub could not be
// reached on the new socket within ctx; the connection is still on its old
// path then.
func (t *ClientTunnel) Migrate(ctx context.Context) error {
	m, ok := t.link.(interface{ migrate(context.Context) error })
	if !ok {
		return ErrNoMigration
	}
	return m.migrate(ctx)
}

// LocalPrefixes returns the addresses the gateway assigned.
func (t *ClientTunnel) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return t.link.LocalPrefixes(ctx)
}

// Routes returns the routes the gateway advertised.
func (t *ClientTunnel) Routes(ctx context.Context) ([]connectip.IPRoute, error) {
	return t.link.Routes(ctx)
}

// Done is closed when the connection ends; Err then explains why.
func (t *ClientTunnel) Done() <-chan struct{} { return t.link.Done() }

// Err returns the reason the connection ended, or nil while it is alive.
func (t *ClientTunnel) Err() error { return t.link.Err() }

// Close ends the tunnel cleanly.
func (t *ClientTunnel) Close() error { return t.link.Close(0, "client closed") }

// Abandon ends a tunnel this side no longer trusts to carry packets (it did
// not follow a network change): ErrCodeNoAnswer, so that the owner dials
// again at once.
func (t *ClientTunnel) Abandon(reason string) error {
	return t.link.Close(ErrCodeNoAnswer, reason)
}
