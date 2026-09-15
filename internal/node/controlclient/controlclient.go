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
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// Client for the node API.
type Client struct {
	URL    string // https://control:443
	http   *http.Client
	log     *slog.Logger
	verify  func(*registry.Snapshot) error
	onError func(error)
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
}

// New creates a client presenting the device certificate.
func New(cfg Config) *Client {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	tlsCfg := cfg.TLS
	h3 := &http3.Transport{
		TLSClientConfig: tlsCfg.Clone(),
		QUICConfig:      &quic.Config{MaxIdleTimeout: 90 * time.Second, KeepAlivePeriod: 20 * time.Second},
	}
	tcp := &http.Transport{TLSClientConfig: tlsCfg.Clone(), ForceAttemptHTTP2: true}
	rt := &dualTransport{h3: h3, tcp: tcp, log: cfg.Log}
	return &Client{URL: "https://" + cfg.Addr, http: &http.Client{Transport: rt}, log: cfg.Log, verify: cfg.Verify, onError: cfg.OnError}
}

// dualTransport prefers HTTP/3 and falls back to TCP when the QUIC dial or
// request fails before a response arrived. It retries HTTP/3 periodically
// so a temporary UDP problem does not stick.
type dualTransport struct {
	h3  *http3.Transport
	tcp *http.Transport
	log *slog.Logger

	mu           sync.Mutex
	tcpUntil     time.Time
	fallbackSeen bool
}

const h3RetryAfter = 5 * time.Minute

func (d *dualTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	useTCP := time.Now().Before(d.tcpUntil)
	d.mu.Unlock()
	if useTCP {
		return d.tcp.RoundTrip(req)
	}
	rsp, err := d.h3.RoundTrip(req)
	if err == nil {
		d.mu.Lock()
		if d.fallbackSeen {
			d.log.Info("control plane reachable over HTTP/3 again")
			d.fallbackSeen = false
		}
		d.mu.Unlock()
		return rsp, nil
	}
	if req.Context().Err() != nil {
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
	return d.tcp.RoundTrip(req)
}

// Close releases connections.
func (c *Client) Close() {
	if rt, ok := c.http.Transport.(*dualTransport); ok {
		_ = rt.h3.Close()
		rt.tcp.CloseIdleConnections()
	}
}

// APIError carries the HTTP status of a refused request.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("control plane: HTTP %d: %s", e.Status, e.Message) }

// ErrNotApproved is returned when the control plane refuses the node
// (pending, revoked or unknown).
var ErrNotApproved = errors.New("controlclient: node not approved")

func (c *Client) do(ctx context.Context, method, path string, in, out any, timeout time.Duration) (int, error) {
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
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
	for ctx.Err() == nil {
		snap, err := c.Snapshot(ctx, since, 30*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrNotApproved) {
				return err
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
			continue
		}
		since = snap.Version
		if c.verify != nil {
			if err := c.verify(snap); err != nil {
				// our own record does not verify: operate with nothing
				// rather than with a snapshot we cannot trust
				c.log.Error("snapshot rejected", "version", snap.Version, "err", err)
				holder.Clear()
				continue
			}
		}
		diff := holder.Store(snap)
		c.log.Info("snapshot applied", "version", snap.Version, "peers", len(snap.Peers), "hubs", len(snap.Hubs()), "added", diff.AddedPeers, "removed", diff.RemovedPeers)
		if onDiff != nil {
			onDiff(diff, snap)
		}
	}
	return nil
}
