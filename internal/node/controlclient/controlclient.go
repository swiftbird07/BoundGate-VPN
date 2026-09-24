// Package controlclient is the node's client for the control plane's node
// API. Every request carries the device certificate (mTLS); the control
// plane decides what an unapproved key may do.
//
// Transport: HTTP/3 over UDP/443 first, TCP/443 (HTTP/2) as fallback when
// UDP does not get through. Both use the same TLS identity and the node
// server name (SNI), which is how the control plane tells nodes from
// browsers on the shared port.
package controlclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// Client for the node API.
type Client struct {
	URL     string // https://control:443
	http    *http.Client
	log     *slog.Logger
	verify  func(*registry.Snapshot) error
	onError func(error)
	poll    time.Duration
	kick    chan struct{}

	// gen ends when Reconnect is called: requests in flight belong to
	// connections that may no longer lead anywhere
	mu        sync.Mutex
	gen       context.Context
	genCancel context.CancelFunc
}

// Config for New.
type Config struct {
	// Addr is host:port of the control plane, e.g. control.example:443.
	Addr string
	// TLS is the client configuration: device certificate, node server
	// name and the control-plane key pin (transport.ClientTLSConfigControl).
	TLS *tls.Config
	Log *slog.Logger
	// Verify, if set, runs on every received snapshot before it is
	// installed (binding verification). An error means the node's own
	// record is invalid: the snapshot is dropped and the holder cleared.
	Verify func(*registry.Snapshot) error
	// OnError, if set, reports the state of the control channel from the
	// snapshot loop: the error of a failed fetch, nil after a successful one.
	OnError func(error)
	// Resolve, if set, turns the control plane's host name into the address
	// to dial (the node's address book: what it excluded from its tunnel).
	Resolve func(ctx context.Context, host string) (netip.Addr, error)
	// Poll, when set, replaces the long-poll: Run asks for the snapshot
	// this often, and at once after Refresh or Reconnect. Nothing is kept
	// open in between (no keep-alives, no pings), so a phone's radio can
	// sleep. Zero: the long-poll, which learns of changes within a second.
	Poll time.Duration
}

// New creates a client presenting the device certificate.
func New(cfg Config) *Client {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	rt := &dualTransport{tls: cfg.TLS, log: cfg.Log, resolve: cfg.Resolve, quiet: cfg.Poll > 0}
	rt.h3, rt.tcp = rt.transports()
	c := &Client{URL: "https://" + cfg.Addr, http: &http.Client{Transport: rt}, log: cfg.Log, verify: cfg.Verify, onError: cfg.OnError,
		poll: cfg.Poll, kick: make(chan struct{}, 1)}
	c.gen, c.genCancel = context.WithCancel(context.Background())
	return c
}

// transports makes a fresh pair. A path that stopped carrying packets (the
// machine changed networks, another VPN took over the route) is noticed
// within 30 s instead of only by the request deadline: keep-alives go out
// every 10 s, on QUIC and as HTTP/2 pings, and long-polls are quiet for 30 s.
// Quiet (Config.Poll) sends neither: connections close when idle, and the
// next poll dials again.
func (d *dualTransport) transports() (*http3.Transport, *http.Transport) {
	keepAlive, ping := 10*time.Second, 10*time.Second
	if d.quiet {
		keepAlive, ping = 0, 0
	}
	h3 := &http3.Transport{
		TLSClientConfig: d.tls.Clone(),
		QUICConfig:      &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: keepAlive},
	}
	tcp := &http.Transport{TLSClientConfig: d.tls.Clone(), ForceAttemptHTTP2: true,
		HTTP2: &http.HTTP2Config{SendPingTimeout: ping, PingTimeout: 15 * time.Second}}
	if d.resolve != nil {
		// the TLS configs carry the server name; the dial goes to the address
		h3.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			ap, err := d.addr(ctx, addr)
			if err != nil {
				return nil, err
			}
			return quic.DialAddr(ctx, ap.String(), tlsCfg, cfg)
		}
		tcp.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			ap, err := d.addr(ctx, addr)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, ap.String())
		}
	}
	return h3, tcp
}

// addr resolves host:port through the node's address book.
func (d *dualTransport) addr(ctx context.Context, hostport string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, err := d.resolve(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(p)), nil
}

// errReconnected ends the requests that were in flight at Reconnect.
var errReconnected = errors.New("controlclient: connections were reset after a route change")

// Reconnect drops every connection to the control plane and ends the
// requests waiting on them; the snapshot loop asks again at once. The node
// calls it whenever it changed the machine's routes (overlay up and down
// add and remove the bypass route to the control plane): a connection made
// over the old route keeps its source address and would sit there unanswered
// until its deadline, up to 50 s for a long-poll.
func (c *Client) Reconnect() {
	c.mu.Lock()
	cancel := c.genCancel
	c.gen, c.genCancel = context.WithCancel(context.Background())
	c.mu.Unlock()
	cancel()
	if rt, ok := c.http.Transport.(*dualTransport); ok {
		rt.reset()
	}
	c.Refresh()
}

// Refresh makes a polling Run ask for the snapshot now (the user signed in,
// a hub refused us); the long-poll hears of changes by itself.
func (c *Client) Refresh() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// pause waits until the next poll; false when ctx ended. Without Poll the
// long-poll asks again at once.
func (c *Client) pause(ctx context.Context) bool {
	if c.poll <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(c.poll):
	case <-c.kick:
	}
	return true
}

// Transport says what carried the last answer of the control plane: "h3"
// (HTTP/3 over UDP), "h2" (the TCP fallback) or "" before the first one.
func (c *Client) Transport() string {
	rt, ok := c.http.Transport.(*dualTransport)
	if !ok {
		return ""
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.last
}

// dualTransport prefers HTTP/3 and falls back to TCP when the QUIC dial or
// request fails before a response arrived. It retries HTTP/3 periodically
// so a temporary UDP problem does not stick.
type dualTransport struct {
	tls     *tls.Config
	log     *slog.Logger
	resolve func(ctx context.Context, host string) (netip.Addr, error)
	quiet   bool

	mu           sync.Mutex
	h3           *http3.Transport
	tcp          *http.Transport
	tcpUntil     time.Time
	fallbackSeen bool
	last         string // what carried the last answer: "h3" or "h2"
}

const h3RetryAfter = 5 * time.Minute

func (d *dualTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	useTCP := time.Now().Before(d.tcpUntil)
	h3, tcp := d.h3, d.tcp
	d.mu.Unlock()
	if useTCP {
		return d.overTCP(tcp, req)
	}
	rsp, err := h3.RoundTrip(req)
	if err == nil {
		d.mu.Lock()
		d.last = "h3"
		if d.fallbackSeen {
			d.log.Info("control plane reachable over HTTP/3 again")
			d.fallbackSeen = false
		}
		d.mu.Unlock()
		return rsp, nil
	}
	if req.Context().Err() != nil || answeredOverUDP(err) {
		return nil, err
	}
	// A body may have been consumed; only retry idempotent-safe requests
	// (ours all carry small in-memory bodies, so GetBody is set).
	if req.Body != nil && req.GetBody != nil {
		if req.Body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	d.mu.Lock()
	d.tcpUntil = time.Now().Add(h3RetryAfter)
	if !d.fallbackSeen {
		d.log.Warn("control plane not reachable over HTTP/3 (UDP); falling back to TCP", "err", err)
		d.fallbackSeen = true
	}
	d.mu.Unlock()
	return d.overTCP(tcp, req)
}

// answeredOverUDP: the control plane was reached over UDP and the
// connection failed on its content (a key that is not pinned yet, a refused
// certificate, a closed connection). TCP would fail the same way; falling
// back is for a path that carries no UDP.
func answeredOverUDP(err error) bool {
	var te *quic.TransportError
	var ae *quic.ApplicationError
	return errors.As(err, &te) || errors.As(err, &ae)
}

func (d *dualTransport) overTCP(tcp *http.Transport, req *http.Request) (*http.Response, error) {
	rsp, err := tcp.RoundTrip(req)
	if err == nil {
		d.mu.Lock()
		d.last = "h2"
		d.mu.Unlock()
	}
	return rsp, err
}

// reset replaces both transports and gives HTTP/3 another try: what made it
// fail may have been the old route.
func (d *dualTransport) reset() {
	d.mu.Lock()
	oldH3, oldTCP := d.h3, d.tcp
	d.h3, d.tcp = d.transports()
	d.tcpUntil = time.Time{}
	d.mu.Unlock()
	_ = oldH3.Close()
	oldTCP.CloseIdleConnections()
}

// Close releases connections.
func (c *Client) Close() {
	if rt, ok := c.http.Transport.(*dualTransport); ok {
		rt.mu.Lock()
		h3, tcp := rt.h3, rt.tcp
		rt.mu.Unlock()
		_ = h3.Close()
		tcp.CloseIdleConnections()
	}
}

// APIError carries the HTTP status of a refused request.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control plane: HTTP %d: %s", e.Status, e.Message)
}

// ErrNotApproved is returned when the control plane refuses the node
// (pending, revoked or unknown).
var ErrNotApproved = errors.New("controlclient: node not approved")

func (c *Client) do(ctx context.Context, method, path string, in, out any, timeout time.Duration) (int, error) {
	// a request cut off by Reconnect goes out again over the new connections;
	// every request of this API may be repeated
	for range 2 {
		if status, err := c.doOnce(ctx, method, path, in, out, timeout); !errors.Is(err, errReconnected) {
			return status, err
		}
	}
	return c.doOnce(ctx, method, path, in, out, timeout)
}

func (c *Client) doOnce(ctx context.Context, method, path string, in, out any, timeout time.Duration) (int, error) {
	var rd io.Reader
	var raw []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		raw = b
		rd = bytes.NewReader(b)
	}
	parent := ctx
	c.mu.Lock()
	gen := c.gen
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer context.AfterFunc(gen, cancel)()
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, rd)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	}
	rsp, err := c.http.Do(req)
	if err != nil {
		if gen.Err() != nil && parent.Err() == nil {
			return 0, errReconnected
		}
		// our own deadline, not the caller's: say what happened instead of
		// `Get "https://…/snapshot?since=4&wait=30s": context deadline exceeded`
		if errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil {
			return 0, fmt.Errorf("control plane %s gave no answer within %s (%s %s): %w", c.URL, timeout, method, strings.SplitN(path, "?", 2)[0], context.DeadlineExceeded)
		}
		return 0, fmt.Errorf("control plane %s: %w", c.URL, err)
	}
	defer rsp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(rsp.Body, 64<<20))
	if rsp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		// enroll/status answers 404 with a body we still want
		if out != nil && len(body) > 0 && rsp.StatusCode == http.StatusNotFound {
			_ = json.Unmarshal(body, out)
		}
		if rsp.StatusCode == http.StatusForbidden {
			return rsp.StatusCode, fmt.Errorf("%w: %s", ErrNotApproved, e.Error)
		}
		return rsp.StatusCode, &APIError{Status: rsp.StatusCode, Message: e.Error}
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return rsp.StatusCode, fmt.Errorf("control plane: decode: %w", err)
		}
	}
	return rsp.StatusCode, nil
}

// Enroll submits (or re-submits) the enrollment request.
func (c *Client) Enroll(ctx context.Context, req api.EnrollRequest) (api.EnrollStatus, error) {
	var st api.EnrollStatus
	_, err := c.do(ctx, http.MethodPost, "/api/v1/node/enroll", req, &st, 20*time.Second)
	return st, err
}

// EnrollStatus asks what the control plane thinks of this key. Unknown keys
// return Status "unknown" and no error.
func (c *Client) EnrollStatus(ctx context.Context) (api.EnrollStatus, error) {
	var st api.EnrollStatus
	status, err := c.do(ctx, http.MethodGet, "/api/v1/node/enroll/status", nil, &st, 20*time.Second)
	var apiErr *APIError
	if errors.As(err, &apiErr) && status == http.StatusNotFound {
		st.Status = "unknown"
		return st, nil
	}
	return st, err
}

// LoginStart begins a user login; the returned URL is for the user's browser.
func (c *Client) LoginStart(ctx context.Context) (api.LoginStart, error) {
	var out api.LoginStart
	_, err := c.do(ctx, http.MethodPost, "/api/v1/node/login/start", map[string]any{}, &out, 30*time.Second)
	return out, err
}

// LoginStatus polls a flow, waiting up to wait for a result.
func (c *Client) LoginStatus(ctx context.Context, flowID string, wait time.Duration) (api.LoginStatus, error) {
	var out api.LoginStatus
	_, err := c.do(ctx, http.MethodGet, "/api/v1/node/login/"+flowID+"?wait="+wait.String(), nil, &out, wait+20*time.Second)
	return out, err
}

// Logout ends the node's user session.
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/node/logout", map[string]any{}, nil, 20*time.Second)
	return err
}

// ShipLogs sends a batch of flow records and tunnel reports.
func (c *Client) ShipLogs(ctx context.Context, events []api.ShippedEvent) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/node/logs", api.ShipRequest{Events: events}, nil, 30*time.Second)
	return err
}

// Heartbeat reports liveness.
func (c *Client) Heartbeat(ctx context.Context, version uint64, tunnels int) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/node/heartbeat", map[string]any{"version": version, "active_tunnels": tunnels}, nil, 20*time.Second)
	return err
}

// Snapshot long-polls once. It returns (nil, nil) when nothing newer than
// since arrived within wait, ErrNotApproved when the node lost approval.
func (c *Client) Snapshot(ctx context.Context, since uint64, wait time.Duration) (*registry.Snapshot, error) {
	path := "/api/v1/node/snapshot?since=" + strconv.FormatUint(since, 10) + "&wait=" + wait.String()
	var snap registry.Snapshot
	status, err := c.do(ctx, http.MethodGet, path, nil, &snap, wait+20*time.Second)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotModified {
		return nil, nil
	}
	if err := snap.Validate(); err != nil {
		return nil, err
	}
	return &snap, nil
}

// Run keeps holder current until ctx ends or the node loses approval
// (ErrNotApproved is returned then). onDiff runs after every stored
// snapshot; it is where revocation of peers happens.
func (c *Client) Run(ctx context.Context, holder *registry.Holder, onDiff func(registry.Diff, *registry.Snapshot)) error {
	var since uint64
	if s := holder.Load(); s != nil {
		since = s.Version
	}
	backoff := time.Second
	// polling: answer at once, nothing stays open until the next poll
	wait := 30 * time.Second
	if c.poll > 0 {
		wait = time.Second
	}
	for ctx.Err() == nil {
		snap, err := c.Snapshot(ctx, since, wait)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrNotApproved) {
				return err
			}
			if errors.Is(err, errReconnected) {
				continue // nothing is wrong: ask again over the new route
			}
			if c.onError != nil {
				c.onError(err)
			}
			c.log.Warn("snapshot fetch failed", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if c.onError != nil {
			c.onError(nil)
		}
		if snap == nil {
			holder.Touch()
			if !c.pause(ctx) {
				return nil
			}
			continue
		}
		since = snap.Version
		if c.verify != nil {
			if err := c.verify(snap); err != nil {
				// our own record does not verify: operate with nothing
				// rather than with a snapshot we cannot trust
				c.log.Error("snapshot rejected", "version", snap.Version, "err", err)
				holder.Clear()
				if !c.pause(ctx) {
					return nil
				}
				continue
			}
		}
		diff := holder.Store(snap)
		c.log.Info("snapshot applied", "version", snap.Version, "peers", len(snap.Peers), "hubs", len(snap.Hubs()), "added", diff.AddedPeers, "removed", diff.RemovedPeers)
		if onDiff != nil {
			onDiff(diff, snap)
		}
		if !c.pause(ctx) {
			return nil
		}
	}
	return nil
}
