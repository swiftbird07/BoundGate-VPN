// Package embed runs a node inside an app instead of as a daemon: the packet
// tunnel of the iOS app, a macOS network extension, Android's VpnService.
//
// The app brings what a daemon finds on the host: the device key (Secure
// Enclave, Android Keystore) as a signer, and the network configuration as a
// Platform that takes all settings at once and returns the tunnel's file
// descriptor. Everything else is the same node, and the app talks to it with
// the requests of the daemon's socket (GET /v1/status, POST /v1/up, …) passed
// in memory: the apps share one protocol and one status JSON for both.
package embed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/version"
)

// Config is what the app decides; the control plane's address is not part of
// it: the user enters it once (POST /v1/configure) and it is kept in the
// state directory like on a daemon.
type Config struct {
	// StateDir holds the node's state (certificate, pins, settings). On iOS
	// and macOS the app group container, shared by app and extension.
	StateDir string `json:"state_dir"`
	// Platform is reported at enrollment: ios, android, macos.
	Platform string `json:"platform"`
	// Name is the device name offered at enrollment (the user may change it).
	Name string `json:"name,omitempty"`
	MTU  int    `json:"mtu,omitempty"`
	// AutoUp brings the overlay up once the node is approved: the network
	// extension, which only runs while the user wants the tunnel.
	AutoUp  bool   `json:"auto_up,omitempty"`
	Profile string `json:"profile,omitempty"`
	// Provisioning, as in a daemon's configuration file.
	ControlPin     string            `json:"control_pin,omitempty"`
	SignersGenesis string            `json:"signers_genesis,omitempty"`
	HubAddrs       map[string]string `json:"hub_addrs,omitempty"`
	Transport      string            `json:"transport,omitempty"`
	// MemoryLimitMiB is a soft limit for the Go heap (debug.SetMemoryLimit):
	// an iOS packet tunnel is killed at 50 MiB.
	MemoryLimitMiB int `json:"memory_limit_mib,omitempty"`
	// LogLevel: debug, info (default), warn, error. FlowLog also writes one
	// line per connection to the log (they are shipped to the control plane
	// either way).
	LogLevel string `json:"log_level,omitempty"`
	FlowLog  bool   `json:"flow_log,omitempty"`
}

// Platform is what the app provides.
type Platform interface {
	netcfg.Platform
	Key
	// Log receives one line per record; level as in log/slog (-4 debug,
	// 0 info, 4 warn, 8 error).
	Log(level int, line string)
}

// Key is the device key, held by the platform.
type Key interface {
	// PublicKey is the DER SubjectPublicKeyInfo of an ECDSA P-256 key.
	PublicKey() ([]byte, error)
	// Sign signs a SHA-256 digest; the signature is ASN.1 DER (what
	// SecKeyCreateSignature with ecdsaSignatureDigestX962SHA256 and
	// Android's NONEwithECDSA return).
	Sign(digest []byte) ([]byte, error)
	// KeyKind names the key store: secure-enclave, android-keystore,
	// android-strongbox, softkey.
	KeyKind() string
	// HardwareBound: the private key cannot leave the hardware.
	HardwareBound() bool
}

// ErrBusy: another engine (app or extension) uses the state directory.
var ErrBusy = errors.New("embed: busy: another BoundGate engine uses this state directory (is the tunnel running?)")

// Engine is a running embedded node, or the setup API of one without a
// control plane yet.
type Engine struct {
	cfg  Config
	p    Platform
	key  devicekey.DeviceKey
	log  *slog.Logger
	flow *slog.Logger
	net  *netcfg.Declarative
	lock *os.File

	mu      sync.Mutex
	handler http.Handler
	run     *running
	stopped bool
}

// running is a started node and the goroutine that drives it.
type running struct {
	n      *node.Node
	cancel context.CancelFunc
	done   chan struct{}
}

// stop ends Run first: closing the control client under a request that is
// just starting races inside quic-go's HTTP/3 transport.
func (r *running) stop() {
	r.cancel()
	<-r.done
	r.n.Close()
}

// Start opens the state directory and starts the node, or its setup API when
// no control plane is configured yet.
func Start(cfg Config, p Platform) (*Engine, error) {
	if cfg.StateDir == "" || !filepath.IsAbs(cfg.StateDir) {
		return nil, errors.New("embed: state_dir must be an absolute path")
	}
	if cfg.Platform == "" {
		return nil, errors.New("embed: platform is required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	lock, err := lockDir(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if cfg.MemoryLimitMiB > 0 {
		debug.SetMemoryLimit(int64(cfg.MemoryLimitMiB) << 20)
	}
	log := slog.New(newPlatformHandler(p, parseLevel(cfg.LogLevel)))
	flow := slog.New(discard{})
	if cfg.FlowLog {
		flow = log
	}
	key, err := newPlatformKey(p)
	if err != nil {
		lock.Close()
		return nil, err
	}
	e := &Engine{cfg: cfg, p: p, key: key, log: log, flow: flow, lock: lock, net: netcfg.NewDeclarative(p, log)}
	log.Info("engine starting", "platform", cfg.Platform, "version", version.Version, "key_kind", key.Kind(), "memory_limit_mib", cfg.MemoryLimitMiB)
	s, err := ipc.LoadSettings(e.settingsPath())
	if err != nil {
		lock.Close()
		return nil, err
	}
	if s.ControlAddr == "" {
		e.setup()
		return e, nil
	}
	if err := e.startNode(s); err != nil {
		lock.Close()
		return nil, err
	}
	return e, nil
}

func (e *Engine) settingsPath() string { return filepath.Join(e.cfg.StateDir, "settings.json") }

// setup serves the API of a node without a control plane.
func (e *Engine) setup() {
	spki, _ := devicekey.HashPublicKey(e.key.Public())
	st := node.Status{NodeName: e.cfg.Name, Enrollment: "unknown", KeyKind: e.key.Kind(), HardwareBound: e.key.HardwareBound(),
		SPKI: spki.String(), Fingerprint: spki.Fingerprint()}
	h := ipc.SetupHandler(st, nil, func(s ipc.Settings) error {
		// the node takes over for the next request; if it cannot start (the
		// user refused the key), the answer says so and nothing is stored
		if err := ipc.SaveSettings(e.settingsPath(), s); err != nil {
			return err
		}
		if err := e.startNode(s); err != nil {
			_ = os.Remove(e.settingsPath())
			return err
		}
		return nil
	}, func(ipc.Settings) {})
	e.mu.Lock()
	e.handler = h
	e.mu.Unlock()
}

func (e *Engine) startNode(s ipc.Settings) error {
	name := s.Name
	if name == "" {
		name = e.cfg.Name
	}
	n, err := node.New(node.Config{
		Name:              name,
		StateDir:          e.cfg.StateDir,
		ControlAddr:       s.ControlAddr,
		ControlServerName: s.ControlServerName,
		ControlPin:        e.cfg.ControlPin,
		SignersGenesis:    e.cfg.SignersGenesis,
		Roles:             []string{"endpoint"},
		Transport:         e.cfg.Transport,
		AutoUp:            e.cfg.AutoUp,
		Profile:           e.cfg.Profile,
		HubAddrs:          e.cfg.HubAddrs,
		MTU:               e.cfg.MTU,
		// no paths.listen: peers reach an embedded node through relaying
		// hubs only (a phone has no stable public address)
		Key:      e.key,
		Net:      e.net,
		Platform: e.cfg.Platform,
		Log:      e.log,
		FlowLog:  e.flow,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{n: n, cancel: cancel, done: make(chan struct{})}
	go func() { defer close(r.done); n.Run(ctx) }()
	h := ipc.Handler(n, ipc.Options{Reset: func(newIdentity bool) error {
		if newIdentity {
			return errors.New("a new identity is a new key in the app's key store: the app deletes its key and starts again")
		}
		return ipc.Forget(e.cfg.StateDir, e.settingsPath(), false)
	}}, func() {
		// answered: stop the node and go back to setup
		go e.resetToSetup()
	})
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		e.mu.Unlock()
		r.stop()
		e.mu.Lock()
		return errors.New("embed: stopped")
	}
	e.run, e.handler = r, h
	return nil
}

func (e *Engine) resetToSetup() {
	time.Sleep(100 * time.Millisecond)
	e.mu.Lock()
	r := e.run
	e.run = nil
	e.mu.Unlock()
	if r != nil {
		r.stop()
	}
	e.setup()
}

// Request serves one request of the daemon's API (internal/node/ipc) and
// returns the status code and the JSON answer.
func (e *Engine) Request(method, path string, body []byte) (int, []byte) {
	e.mu.Lock()
	h, stopped := e.handler, e.stopped
	e.mu.Unlock()
	if stopped || h == nil {
		return http.StatusServiceUnavailable, []byte(`{"error":"the BoundGate engine is stopped"}`)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequest(method, "http://engine"+path, bytes.NewReader(body))
	if err != nil {
		return http.StatusBadRequest, []byte(fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
	req.ContentLength = int64(len(body))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	w := &recorder{header: http.Header{}, status: http.StatusOK}
	h.ServeHTTP(w, req)
	return w.status, w.body.Bytes()
}

// NetworkChanged tells the node the device moved to another network. The
// platform gets the network settings again (Refresh): what it adds from the
// network below, DNS on Android, changes with it.
func (e *Engine) NetworkChanged() {
	e.mu.Lock()
	r := e.run
	e.mu.Unlock()
	if r != nil {
		r.n.NetworkChanged()
	}
	e.net.Refresh()
}

// Stop takes the overlay down and releases the state directory.
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	r := e.run
	e.run, e.handler = nil, nil
	e.mu.Unlock()
	if r != nil {
		r.stop()
	}
	e.lock.Close()
}

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
}
