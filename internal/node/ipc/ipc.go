// Package ipc is the local control channel between boundgatectl (or a GUI)
// and the node daemon: HTTP over a Unix socket with a fixed, small set of
// verbs. Nothing here can touch the device key, install arbitrary routes or
// run commands; it can only ask the daemon to do the things it does anyway.
package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// UpRequest selects the routing profile ("" = default).
type UpRequest struct {
	Profile string `json:"profile"`
}

// EnrollRequest names the node for the admin.
type EnrollRequest struct {
	Name string `json:"name"`
	// AcceptPin: the control plane fingerprint the user accepted, or "new"
	// to pin whatever is presented (scripts). Only used while nothing is
	// pinned; see node.Enroll.
	AcceptPin string `json:"accept_pin,omitempty"`
}

// ErrorResponse is returned for failures.
type ErrorResponse struct {
	Error string `json:"error"`
	// ControlPin is set (status 409) when enrollment needs the user to accept
	// this control plane fingerprint first.
	ControlPin string `json:"control_pin,omitempty"`
}

// PinUnconfirmedError is what Client.Enroll returns in that case.
type PinUnconfirmedError struct{ Fingerprint string }

func (e *PinUnconfirmedError) Error() string {
	return "the control plane presents a key that is not pinned yet: " + e.Fingerprint
}

// Options of the node socket.
type Options struct {
	// Group owns the socket next to root ("" = root's group).
	Group string
	// Reset, when set, makes the node forget its control plane (settings,
	// pin, admin key list), and with newIdentity its device key as well.
	// The node must be down. Serve returns ErrReset after answering.
	Reset func(newIdentity bool) error
}

// ResetRequest is the optional body of POST /v1/reset.
type ResetRequest struct {
	// NewIdentity also discards the device key: the node comes back with a
	// new one (of the configured kind) and has to enroll again.
	NewIdentity bool `json:"new_identity"`
}

// ErrReset is returned by Serve after a successful reset.
var ErrReset = errors.New("ipc: node was reset")

// Serve runs the IPC server until ctx ends. The socket is created with mode
// 0660 so only root and the socket's group can talk to the daemon.
func Serve(ctx context.Context, socketPath string, n *node.Node, opt Options) error {
	ln, err := listen(socketPath, opt.Group)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wasReset atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/configure", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "this node already has a control plane; `boundgatectl reset` forgets it"})
	})
	mux.HandleFunc("POST /v1/reset", func(w http.ResponseWriter, r *http.Request) {
		if opt.Reset == nil {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "the control plane of this node is set in its configuration file"})
			return
		}
		if n.Status().State != node.StateDown {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "disconnect first (boundgatectl down)"})
			return
		}
		var body ResetRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad request body"})
				return
			}
		}
		if err := opt.Reset(body.NewIdentity); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		wasReset.Store(true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
		go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, n.Status())
	})
	mux.HandleFunc("GET /v1/flows", func(w http.ResponseWriter, r *http.Request) {
		fl := n.Flows()
		if fl == nil {
			fl = []node.FlowView{}
		}
		writeJSON(w, http.StatusOK, fl)
	})
	mux.HandleFunc("GET /v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		names, err := n.Profiles()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, names)
	})
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req EnrollRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid body"})
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		st, err := n.Enroll(ctx, req.Name, req.AcceptPin)
		var unconfirmed *node.PinUnconfirmedError
		if errors.As(err, &unconfirmed) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: err.Error(), ControlPin: unconfirmed.Fingerprint})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
	mux.HandleFunc("POST /v1/up", func(w http.ResponseWriter, r *http.Request) {
		var req UpRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid body"})
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := n.Up(ctx, req.Profile); err != nil {
			writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, n.Status())
	})
	mux.HandleFunc("POST /v1/down", func(w http.ResponseWriter, r *http.Request) {
		n.Down("down by user")
		writeJSON(w, http.StatusOK, n.Status())
	})
	mux.HandleFunc("POST /v1/login", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		st, err := n.Login(ctx)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
	mux.HandleFunc("GET /v1/login/{flow}", func(w http.ResponseWriter, r *http.Request) {
		wait := 25 * time.Second
		if v := r.URL.Query().Get("wait"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d >= 0 && d <= 50*time.Second {
				wait = d
			}
		}
		st, err := n.LoginWait(r.Context(), r.PathValue("flow"), wait)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := n.Logout(ctx); err != nil {
			writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, n.Status())
	})
	if err := serveMux(ctx, ln, socketPath, mux); err != nil {
		return err
	}
	if wasReset.Load() {
		return ErrReset
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Client talks to the node socket.
type Client struct {
	Socket string
	http   *http.Client
}

// NewClient returns a client for the socket path.
func NewClient(socket string) *Client {
	return &Client{Socket: socket, http: &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}}
}

func (c *Client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://node"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rsp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("node daemon not reachable at %s: %w", c.Socket, err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		var e ErrorResponse
		_ = json.NewDecoder(rsp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = rsp.Status
		}
		if e.ControlPin != "" {
			return &PinUnconfirmedError{Fingerprint: e.ControlPin}
		}
		return errors.New(e.Error)
	}
	if out != nil {
		return json.NewDecoder(rsp.Body).Decode(out)
	}
	return nil
}

// Status fetches the daemon status.
func (c *Client) Status() (node.Status, error) {
	var s node.Status
	err := c.do(http.MethodGet, "/v1/status", nil, &s)
	return s, err
}

// Flows lists the tracked flows.
func (c *Client) Flows() ([]node.FlowView, error) {
	var fl []node.FlowView
	err := c.do(http.MethodGet, "/v1/flows", nil, &fl)
	return fl, err
}

// Profiles lists profile names.
func (c *Client) Profiles() ([]string, error) {
	var names []string
	err := c.do(http.MethodGet, "/v1/profiles", nil, &names)
	return names, err
}

// Enroll submits the enrollment request.
func (c *Client) Enroll(name, acceptPin string) (api.EnrollStatus, error) {
	var st api.EnrollStatus
	err := c.do(http.MethodPost, "/v1/enroll", EnrollRequest{Name: name, AcceptPin: acceptPin}, &st)
	return st, err
}

// Up asks the daemon to bring the overlay up with a profile.
func (c *Client) Up(profile string) (node.Status, error) {
	var s node.Status
	err := c.do(http.MethodPost, "/v1/up", UpRequest{Profile: profile}, &s)
	return s, err
}

// Login starts a user login; the URL is for the user's browser.
func (c *Client) Login() (api.LoginStart, error) {
	var st api.LoginStart
	err := c.do(http.MethodPost, "/v1/login", nil, &st)
	return st, err
}

// LoginWait polls the login flow for up to wait.
func (c *Client) LoginWait(flowID string, wait time.Duration) (api.LoginStatus, error) {
	var st api.LoginStatus
	err := c.do(http.MethodGet, "/v1/login/"+flowID+"?wait="+wait.String(), nil, &st)
	return st, err
}

// Logout ends the user session.
func (c *Client) Logout() (node.Status, error) {
	var s node.Status
	err := c.do(http.MethodPost, "/v1/logout", nil, &s)
	return s, err
}

// Configure tells a daemon in setup mode which control plane it belongs to.
func (c *Client) Configure(s Settings) error {
	return c.do(http.MethodPost, "/v1/configure", s, nil)
}

// Reset makes the daemon forget its control plane.
func (c *Client) Reset(newIdentity bool) error {
	if !newIdentity {
		return c.do(http.MethodPost, "/v1/reset", nil, nil)
	}
	return c.do(http.MethodPost, "/v1/reset", ResetRequest{NewIdentity: true}, nil)
}

// Down asks the daemon to tear the overlay down.
func (c *Client) Down() (node.Status, error) {
	var s node.Status
	err := c.do(http.MethodPost, "/v1/down", nil, &s)
	return s, err
}
