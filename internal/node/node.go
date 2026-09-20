// Package node is the privileged daemon every BoundGate participant runs.
// It owns the device key, keeps the control channel (enrollment, registry
// snapshots), and depending on its granted roles accepts tunnels (hub),
// dials hubs (everything else), announces prefixes (subnet router, exit
// node) and configures TUN, routes and NAT. The CLI/GUI talk to it over a
// narrow local IPC (package ipc) and never see the key.
package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/quic-go/quic-go"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/acl"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicecert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/sekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/tpm2key"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/controlclient"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/profile"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/version"
)

// Config for the daemon.
type Config struct {
	Name string
	// StateDir holds device.key and device.crt.
	StateDir string
	// KeyKind selects the DeviceKey implementation: "softkey" (default),
	// "tpm2" (a key created in and bound to the machine's TPM 2.0),
	// "secure-enclave" (the same in a Mac's Secure Enclave), or "auto": keep
	// the identity this node already has, and on a fresh state directory take
	// the Secure Enclave where there is one and a software key elsewhere.
	KeyKind string
	// SEKeyHelper is the Secure Enclave helper for kind secure-enclave;
	// default: boundgate-sekey next to this executable.
	SEKeyHelper string
	// TPMDevice is the TPM for key kind tpm2: a device path (default
	// /dev/tpmrm0; a VM's vTPM appears there as well) or unix:PATH /
	// tcp:HOST:PORT for a software TPM (swtpm).
	TPMDevice string
	// ControlAddr is host:port of the control plane (port 443).
	ControlAddr string
	// ControlServerName is the node SNI, default "nodes." + host of ControlAddr.
	ControlServerName string
	// ControlPin is the hex SPKI hash of the control plane's node-channel
	// key, if provisioned. Empty: trust on first use, stored in
	// StateDir/control.pin and shown by `boundgatectl identity`.
	ControlPin string
	// SignersGenesis is the hex SHA-256 of the genesis admin key list, if
	// provisioned. Empty: the signed list is pinned on first use. Either
	// way later lists are only accepted along the signed chain.
	SignersGenesis string
	// Roles and Prefixes are what the node asks for at enrollment; an admin
	// grants them (or not). PublicAddr is announced for the hub role.
	Roles      []string
	Prefixes   []registry.Prefix
	PublicAddr string
	// Listen is the hub tunnel listener (UDP), default ":443".
	Listen string
	// BehindMux: the hub shares its public port with other servers behind a
	// boundgate-mux. Listen is then the private address the mux delivers to.
	BehindMux *BehindMux
	// NoTCPFallback: a hub serves tunnels on UDP only, and a spoke never
	// tries TCP. Default: hubs also listen on TCP at Listen (the same
	// tunnel over TLS on TCP/443 for networks that block UDP) and spokes
	// fall back to it when the QUIC handshake gets no answer.
	NoTCPFallback bool
	// Transport is the spoke's preference: "auto" (QUIC, then TCP; back to
	// QUIC when it works again), "quic" (never TCP), "tcp" (always TCP).
	Transport string
	// QUICRetry is how often a spoke on TCP tries QUIC again. Default 2m.
	QUICRetry time.Duration
	// NoRelay: a hub does not relay between spokes (transport/relay.go).
	NoRelay bool
	// NoPaths: a spoke neither dials nor accepts tunnels with other spokes;
	// everything stays on the hub path (paths.go).
	NoPaths bool
	// PathsListen is a UDP address peers can dial this spoke at; PublicAddr
	// is what they are told. Empty: reachable through relaying hubs only.
	PathsListen string
	// PathIdle closes a dialed path nothing used for this long. Default 5m.
	PathIdle time.Duration
	// AutoUp brings the overlay up as soon as the first snapshot arrives
	// (servers, hubs, routers). Interactive endpoints use `boundgatectl up`.
	AutoUp bool
	// Profile is the default routing profile name ("" = everything advertised).
	Profile     string
	ProfilesDir string
	TUNName     string
	MTU         int
	// HubAddrs overrides where a hub is dialed, keyed by hub name or by its
	// advertised public_addr (both unsigned). For networks where the
	// advertised address is not reachable as is: the compose lab from the
	// Mac host, split-horizon DNS, port forwards. The hub is still
	// authenticated by its pinned key, whatever address answers.
	HubAddrs map[string]string
	// AllowOverlap disables the overlap guard: routes are installed even
	// when this machine has an address inside them (see overlap.go).
	AllowOverlap bool
	Log          *slog.Logger
	// FlowLog receives one record per flow open/deny/close (the "flow"
	// stream); nil means the system log.
	FlowLog *slog.Logger
}

// State of the overlay.
type State string

const (
	StateDown     State = "down"
	StateStarting State = "starting"
	StateUp       State = "up"
)

// BehindMux configures a server behind a front (internal/mux).
type BehindMux struct {
	// ID is the first byte of this server's QUIC connection IDs; the mux
	// routes established connections by it. Unique per mux.
	ID byte
	// Trusted are the addresses the mux delivers from.
	Trusted []netip.Prefix
	// NoProxyProtocol: the TCP front sends no PROXY v2 header, so the hub
	// sees the front's address instead of the client's on TCP tunnels.
	NoProxyProtocol bool
}

// UserStatus is the node's user session as the CLI shows it.
type UserStatus struct {
	Subject   string    `json:"subject"`
	Username  string    `json:"username,omitempty"`
	Email     string    `json:"email,omitempty"`
	Groups    []string  `json:"groups"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Status is what the CLI shows.
type Status struct {
	State     State           `json:"state"`
	Profile   string          `json:"profile,omitempty"`
	OverlayIP string          `json:"overlay_ip,omitempty"`
	Kind      registry.Kind   `json:"kind,omitempty"`
	Roles     []registry.Role `json:"roles,omitempty"`
	// User is the active user session bound to this node (interactive nodes).
	User *UserStatus `json:"user,omitempty"`
	// LoginRequired is set when a hub refused the node for lack of a session.
	LoginRequired bool        `json:"login_required,omitempty"`
	Prefixes      []string    `json:"prefixes,omitempty"`
	Hubs          []HubStatus `json:"hubs,omitempty"`
	// Paths are tunnels with other spokes, direct or through a hub's relay.
	Paths  []PathStatus `json:"paths,omitempty"`
	Routes []string     `json:"routes,omitempty"`
	// SkippedRoutes are advertised networks the node refused to route
	// because this machine already lives in them (overlap guard).
	SkippedRoutes []string `json:"skipped_routes,omitempty"`
	Tunnels       int      `json:"tunnels"` // accepted tunnels (hub role)
	// Relay: what this hub relays between spokes right now and relayed so far.
	Relay         *transport.RelayStats `json:"relay,omitempty"`
	Since         time.Time             `json:"since,omitempty"`
	LastError     string                `json:"last_error,omitempty"`
	LastClose     string                `json:"last_close,omitempty"`
	NodeName      string                `json:"node_name"`
	NodeID        string                `json:"node_id,omitempty"`
	SPKI          string                `json:"spki"`
	Fingerprint   string                `json:"fingerprint"`
	KeyKind       string                `json:"key_kind"`
	Version       string                `json:"version"` // release tag of this daemon, or "dev"
	HardwareBound bool                  `json:"hardware_bound"`
	// KeyWarning is set when the device key is weaker than it should be (a
	// software key on a Mac); HardwareKeyAvailable: a new identity
	// (`reset -new-identity`) would be hardware-bound.
	KeyWarning           string `json:"key_warning,omitempty"`
	HardwareKeyAvailable bool   `json:"hardware_key_available,omitempty"`
	Enrollment           string `json:"enrollment"` // unknown | pending | confirmed | approved | revoked
	EnrollmentError      string `json:"enrollment_error,omitempty"`
	Control              string `json:"control"`
	// ControlError is the last error of the control channel ("" = fine).
	ControlError string `json:"control_error,omitempty"`
	// ControlPin is the fingerprint of the pinned control-plane key.
	ControlPin string `json:"control_pin,omitempty"`
	// AdminKeys are the admin signing keys this node accepts (type + SHA256
	// fingerprint), AdminSetVersion the version of that signed list.
	AdminKeys       []string `json:"admin_keys,omitempty"`
	AdminSetVersion uint64   `json:"admin_set_version,omitempty"`
	// AdminTrustError is set while the control plane delivers an admin key
	// list that does not continue the pinned one (the node keeps its list).
	AdminTrustError string `json:"admin_trust_error,omitempty"`
	// Binding reports the state of the node's own signed binding:
	// "verified", "" (no snapshot yet) or an error text.
	Binding      string `json:"binding,omitempty"`
	BindingError string `json:"binding_error,omitempty"`
	// IgnoredPeers lists peers whose binding did not verify (name: reason).
	IgnoredPeers    []string `json:"ignored_peers,omitempty"`
	SnapshotVersion uint64   `json:"snapshot_version"`
	// Policies is the number of compiled ACL statements; PolicyErrors lists
	// policies that did not compile (skipped).
	Policies     int      `json:"policies"`
	PolicyErrors []string `json:"policy_errors,omitempty"`
	// Flows is the number of tracked flows, FlowsDenied the denials since start.
	Flows       int    `json:"flows"`
	FlowsDenied uint64 `json:"flows_denied"`
}

// Node is the daemon state.
type Node struct {
	cfg     Config
	log     *slog.Logger
	key     devicekey.DeviceKey
	spki    devicekey.SPKIHash
	cert    tls.Certificate
	net     netcfg.Configurator
	control *controlclient.Client
	holder  *registry.Holder
	pins    transport.PinStore

	trust *trustStore

	acl     atomic.Pointer[acl.Engine]
	ship    *shipper
	flowLog *slog.Logger
	denied  atomic.Uint64

	mu       sync.Mutex
	status   Status
	sess     *session
	autoDone bool
}

// New opens (or creates) the device key and certificate.
func New(cfg Config) (*Node, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.TUNName == "" {
		cfg.TUNName = "bg0"
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	switch cfg.Transport {
	case "", "auto":
		cfg.Transport = "auto"
	case "quic", "tcp":
	default:
		return nil, fmt.Errorf("node: transport %q: want auto, quic or tcp", cfg.Transport)
	}
	if cfg.NoTCPFallback && cfg.Transport == "tcp" {
		return nil, errors.New("node: transport tcp with tcp_fallback: false")
	}
	if cfg.QUICRetry == 0 {
		cfg.QUICRetry = 2 * time.Minute
	}
	if cfg.PathIdle == 0 {
		cfg.PathIdle = 5 * time.Minute
	}
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	if cfg.ControlAddr == "" {
		return nil, errors.New("node: control address is required")
	}
	if !strings.Contains(cfg.ControlAddr, ":") {
		cfg.ControlAddr += ":443"
	}
	if cfg.ControlServerName == "" {
		host, _, _ := net.SplitHostPort(cfg.ControlAddr)
		cfg.ControlServerName = "nodes." + host
	}
	if _, err := registry.ParseRoles(cfg.Roles); err != nil {
		return nil, err
	}
	for _, p := range cfg.Prefixes {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	var opener devicekey.Opener
	kind := cfg.KeyKind
	enclave := false
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		enclave = sekey.Available(ctx, cfg.SEKeyHelper)
		cancel()
	}
	if kind == "auto" {
		kind = autoKeyKind(cfg, enclave)
	}
	switch kind {
	case "", "softkey":
		opener = softkey.New(filepath.Join(cfg.StateDir, "device.key"))
	case tpm2key.Kind:
		opener = tpm2key.New(cfg.TPMDevice, filepath.Join(cfg.StateDir, "device.tpm"))
		if _, err := os.Stat(filepath.Join(cfg.StateDir, "device.key")); err == nil {
			cfg.Log.Warn("a software key exists next to the TPM key: this node now has a new identity and must enroll again; remove device.key once it is no longer needed")
		}
	case sekey.Kind:
		opener = sekey.New(cfg.SEKeyHelper, filepath.Join(cfg.StateDir, "device.sekey"))
		if _, err := os.Stat(filepath.Join(cfg.StateDir, "device.key")); err == nil {
			cfg.Log.Warn("a software key exists next to the Secure Enclave key: this node now has a new identity and must enroll again; remove device.key once it is no longer needed")
		}
	default:
		return nil, fmt.Errorf("node: unsupported key kind %q", cfg.KeyKind)
	}
	key, err := opener.Open(context.Background())
	if err != nil {
		return nil, err
	}
	cert, err := devicecert.LoadOrCreate(filepath.Join(cfg.StateDir, "device.crt"), key, cfg.Name)
	if err != nil {
		return nil, err
	}
	spki, err := devicekey.HashPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, log: cfg.Log, key: key, spki: spki, cert: cert, net: netcfg.NewJournal(netcfg.New(), filepath.Join(cfg.StateDir, "netstate.json")), holder: &registry.Holder{}, flowLog: cfg.FlowLog}
	if n.flowLog == nil {
		n.flowLog = cfg.Log
	}
	// control-plane pin: provisioned by config, else learned on first use
	if cfg.ControlPin != "" {
		pin, err := devicekey.ParseSPKIHash(cfg.ControlPin)
		if err != nil {
			return nil, fmt.Errorf("node: control.pin: %w", err)
		}
		n.pins = transport.NewMemPin(pin)
	} else {
		n.pins = &filePin{path: filepath.Join(cfg.StateDir, "control.pin")}
	}
	if n.trust, err = loadTrust(cfg.StateDir, strings.ToLower(strings.TrimSpace(cfg.SignersGenesis))); err != nil {
		return nil, err
	}
	// filePin never learns by itself (Enroll asks), so nothing to report here
	var onLearn func(devicekey.SPKIHash)
	n.control = controlclient.New(controlclient.Config{
		Addr: cfg.ControlAddr,
		TLS:  transport.ClientTLSConfigControl(cert, cfg.ControlServerName, n.pins, onLearn),
		Log:  cfg.Log, Verify: n.verifySnapshot, OnError: n.controlError,
	})
	n.ship = newShipper(n.control, cfg.Log)
	n.status = Status{
		State:                StateDown,
		NodeName:             cfg.Name,
		SPKI:                 spki.String(),
		Fingerprint:          spki.Fingerprint(),
		KeyKind:              key.Kind(),
		Version:              version.Version,
		HardwareBound:        key.HardwareBound(),
		KeyWarning:           keyWarning(key.Kind(), enclave),
		HardwareKeyAvailable: enclave && !key.HardwareBound(),
		Enrollment:           "unknown",
		Control:              cfg.ControlAddr,
		AdminKeys:            n.trust.signers().Fingerprints(),
	}
	n.status.AdminSetVersion = n.trust.current().Version
	if pin, ok := n.pins.Pinned(); ok {
		n.status.ControlPin = pin.Fingerprint()
	}
	if w := keyWarning(key.Kind(), enclave); w != "" {
		cfg.Log.Warn("SOFTWARE DEVICE KEY: " + w)
	}
	cfg.Log.Info("node identity", "name", cfg.Name, "key_kind", key.Kind(), "hardware_bound", key.HardwareBound(), "spki", spki, "control", cfg.ControlAddr,
		"control_pin", n.status.ControlPin, "admin_keys", len(n.status.AdminKeys), "admin_set_version", n.status.AdminSetVersion)
	return n, nil
}

// controlError records the control channel state and explains a pin
// mismatch once per episode.
func (n *Node) controlError(err error) {
	n.mu.Lock()
	prev := n.status.ControlError
	if err == nil {
		n.status.ControlError = ""
	} else {
		n.status.ControlError = err.Error()
	}
	n.mu.Unlock()
	if err != nil && errors.Is(err, transport.ErrControlKeyMismatch) && !strings.Contains(prev, "pinned key") {
		n.log.Error("control plane key changed; refusing to talk to it. If the change is intended, remove control.pin (or update control.pin in the config) and restart", "err", err)
	}
}

// followSigners applies the signed admin key list the control plane
// forwards (at enrollment and with every snapshot). The first delivery is
// pinned; afterwards the list only moves along links signed by one of its
// own keys. A chain that does not verify changes nothing and is reported.
func (n *Node) followSigners(chain []registry.SignerLink) {
	if len(chain) == 0 {
		return
	}
	moved, first, err := n.trust.apply(chain)
	cur := n.trust.current()
	keys := n.trust.signers().Fingerprints()
	n.mu.Lock()
	prevErr := n.status.AdminTrustError
	n.status.AdminKeys, n.status.AdminSetVersion, n.status.AdminTrustError = keys, cur.Version, ""
	if err != nil {
		n.status.AdminTrustError = err.Error()
	}
	n.mu.Unlock()
	switch {
	case err != nil && err.Error() != prevErr:
		n.log.Error("admin key list from the control plane refused; keeping the pinned list", "err", err, "pinned_version", cur.Version, "keys", keys)
	case first:
		n.log.Warn("pinned the signed admin key list on first use; compare these fingerprints with your administrator's", "version", cur.Version, "keys", keys)
	case moved:
		n.log.Warn("admin key list changed, signed by a key of the previous list", "version", cur.Version, "keys", keys)
	}
}

func (n *Node) signers() binding.Signers { return n.trust.signers() }

// applyEnrollStatus records what the control plane said and pins keys.
func (n *Node) applyEnrollStatus(st api.EnrollStatus) {
	n.followSigners(st.SignerChain)
	if st.ControlSPKI != "" {
		if want, err := devicekey.ParseSPKIHash(st.ControlSPKI); err == nil {
			if pin, ok := n.pins.Pinned(); ok && pin != want {
				n.log.Error("control plane reports a node-channel key that differs from the pinned one", "pinned", pin.Fingerprint(), "reported", want.Fingerprint())
			}
		}
	}
	n.mu.Lock()
	n.status.Enrollment, n.status.EnrollmentError, n.status.NodeID = st.Status, "", st.NodeID
	if pin, ok := n.pins.Pinned(); ok {
		n.status.ControlPin = pin.Fingerprint()
	}
	n.mu.Unlock()
}

// verifySnapshot checks every binding against the pinned admin keys. Peers
// that fail are dropped (and listed in the status); if the node's own
// binding fails the snapshot is refused and the overlay goes down.
func (n *Node) verifySnapshot(s *registry.Snapshot) error {
	n.followSigners(s.SignerChain) // first: bindings are judged by the list this snapshot brings, if it is legitimate
	rejected, err := binding.VerifySnapshot(s, n.signers())
	n.mu.Lock()
	n.status.IgnoredPeers = nil
	for _, r := range rejected {
		n.status.IgnoredPeers = append(n.status.IgnoredPeers, r.Name+": "+r.Err.Error())
	}
	if err != nil {
		n.status.Binding, n.status.BindingError = "invalid", err.Error()
		n.autoDone = false // come back automatically once the binding verifies again
	} else {
		n.status.Binding, n.status.BindingError = "verified", ""
	}
	n.mu.Unlock()
	for _, r := range rejected {
		n.log.Warn("peer ignored: binding does not verify", "peer", r.Name, "node", r.ID, "err", r.Err)
	}
	if err != nil {
		n.Down("own binding does not verify: " + err.Error())
		return err
	}
	return nil
}

// filePin stores the control-plane pin in the state directory. It does not
// pin on first use by itself: the first key a control plane presents is only
// remembered (seen), the connection is refused, and Enroll pins what the
// person at the keyboard accepted. Whoever answers at the configured address
// first would otherwise be this node's control plane for good.
type filePin struct {
	mu      sync.Mutex
	path    string
	seen    devicekey.SPKIHash
	hasSeen bool
}

// ErrPinUnconfirmed refuses a control plane whose key nobody has accepted yet.
var ErrPinUnconfirmed = errors.New("the key of this control plane has not been accepted yet; enrolling shows it for comparison")

// PinUnconfirmedError is Enroll's answer while no key is pinned: the
// fingerprint the control plane presented, for a person to compare.
type PinUnconfirmedError struct{ Fingerprint string }

func (e *PinUnconfirmedError) Error() string {
	return "the control plane presents a key that is not pinned yet: " + e.Fingerprint
}

func (f *filePin) Pinned() (devicekey.SPKIHash, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path)
	if err != nil {
		return devicekey.SPKIHash{}, false
	}
	h, err := devicekey.ParseSPKIHash(string(b))
	if err != nil {
		return devicekey.SPKIHash{}, false
	}
	return h, true
}

// Learn implements transport.PinStore: remember, do not trust.
func (f *filePin) Learn(h devicekey.SPKIHash) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen, f.hasSeen = h, true
	return ErrPinUnconfirmed
}

// Seen returns the key the control plane presented while none was pinned.
func (f *filePin) Seen() (devicekey.SPKIHash, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen, f.hasSeen
}

// Accept pins h.
func (f *filePin) Accept(h devicekey.SPKIHash) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return os.WriteFile(f.path, []byte(h.String()+"\n"), 0o600)
}

// Run drives the control channel until ctx ends: enrollment status, then
// snapshots and heartbeats while approved. It returns when ctx is done.
func (n *Node) Run(ctx context.Context) {
	// a previous process that died without `down` may have left bypass
	// routes (and on Linux NAT rules) behind
	if j, ok := n.net.(*netcfg.Journal); ok {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if c := j.Recover(rctx); c > 0 {
			n.log.Warn("removed network leftovers of a previous run", "entries", c)
		}
		cancel()
	}
	go n.heartbeats(ctx)
	go n.ship.run(ctx)
	for ctx.Err() == nil {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		st, err := n.control.EnrollStatus(sctx)
		cancel()
		if err != nil {
			n.mu.Lock()
			n.status.EnrollmentError = err.Error()
			n.mu.Unlock()
			n.controlError(err)
		} else {
			n.applyEnrollStatus(st)
			n.controlError(nil)
		}
		if err == nil && st.Status == "approved" {
			err = n.control.Run(ctx, n.holder, n.onSnapshot)
			if errors.Is(err, controlclient.ErrNotApproved) {
				n.log.Warn("control plane no longer approves this node")
				n.holder.Clear()
				n.mu.Lock()
				n.status.Enrollment, n.status.SnapshotVersion, n.status.Binding = "revoked", 0, ""
				n.autoDone = false // auto_up nodes come back once approved again
				n.mu.Unlock()
				n.Down("node no longer approved by the control plane")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// onSnapshot reacts to a new registry version.
func (n *Node) onSnapshot(diff registry.Diff, snap *registry.Snapshot) {
	eng := acl.New(snap)
	n.acl.Store(eng)
	for _, pe := range eng.Errors() {
		n.log.Error("policy skipped: does not compile", "policy", pe.Name, "id", pe.ID, "err", pe.Err)
	}
	n.mu.Lock()
	n.status.Policies = eng.Policies()
	n.status.PolicyErrors = nil
	for _, pe := range eng.Errors() {
		n.status.PolicyErrors = append(n.status.PolicyErrors, pe.Error())
	}
	n.status.SnapshotVersion = snap.Version
	n.status.NodeID = string(snap.Self.ID)
	n.status.Kind = snap.Self.Kind
	n.status.User = nil
	if se, ok := snap.SessionFor(snap.Self.ID, time.Now()); ok {
		n.status.User = &UserStatus{Subject: se.Subject, Username: se.Username, Email: se.Email, Groups: se.Groups, ExpiresAt: se.ExpiresAt}
	}
	s := n.sess
	auto := n.cfg.AutoUp && !n.autoDone && s == nil
	if auto {
		n.autoDone = true
	}
	n.mu.Unlock()
	if s != nil {
		s.applyDiff(diff, snap)
	}
	if auto {
		go func() {
			if err := n.Up(context.Background(), n.cfg.Profile); err != nil {
				n.log.Error("auto up failed", "err", err)
			}
		}()
	}
}

func (n *Node) heartbeats(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		snap := n.holder.Load()
		if snap == nil {
			continue
		}
		n.mu.Lock()
		tunnels := 0
		if n.sess != nil && n.sess.srv != nil {
			tunnels = len(n.sess.srv.ActiveDevices())
		}
		n.mu.Unlock()
		hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if err := n.control.Heartbeat(hctx, snap.Version, tunnels); err != nil {
			n.log.Warn("heartbeat failed", "err", err)
		}
		cancel()
	}
}

// Status returns the current status.
func (n *Node) Status() Status {
	n.publishStatus()
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.status
}

// publishStatus refreshes the volatile parts (hub links, routes, tunnels).
func (n *Node) publishStatus() {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.sess
	if s == nil {
		return
	}
	n.status.Hubs, n.status.Routes, n.status.Tunnels, n.status.LoginRequired, n.status.Paths = nil, nil, 0, false, nil
	if s.paths != nil {
		n.status.Paths = s.paths.status()
	}
	if s.spoke != nil {
		n.status.Hubs = s.spoke.hubs()
		n.status.Routes = s.spoke.routes()
		n.status.SkippedRoutes = s.spoke.skippedRoutes()
		n.status.LoginRequired = s.spoke.loginRequired()
	}
	n.status.Relay = nil
	if s.srv != nil {
		n.status.Tunnels = len(s.srv.ActiveDevices())
		if !n.cfg.NoRelay {
			st := s.srv.RelayStats()
			n.status.Relay = &st
		}
	}
	if s.spoke != nil || s.srv != nil {
		n.status.State = StateUp
	}
	n.status.Flows = s.flows.Len()
	n.status.FlowsDenied = n.denied.Load()
}

// Flows lists the tracked flows of the running session.
func (n *Node) Flows() []FlowView {
	n.mu.Lock()
	s := n.sess
	n.mu.Unlock()
	if s == nil {
		return nil
	}
	snap := n.holder.Load()
	entries := s.flows.Snapshot()
	out := make([]FlowView, 0, len(entries))
	for _, e := range entries {
		out = append(out, flowView(snap, e))
	}
	return out
}

// AcceptNewPin as acceptPin pins whatever key the control plane presents
// (trust on first use without a person: scripts, the lab).
const AcceptNewPin = "new"

// confirmPin makes sure a control plane key is pinned before anything is
// sent. Without a pin: acceptPin "" reports the presented fingerprint as
// *PinUnconfirmedError, a fingerprint pins exactly that key (the handshake
// then enforces it), AcceptNewPin pins what is presented.
func (n *Node) confirmPin(ctx context.Context, acceptPin string) error {
	fp, ok := n.pins.(*filePin)
	if !ok {
		return nil // provisioned by configuration
	}
	if _, pinned := fp.Pinned(); pinned {
		return nil
	}
	if acceptPin != "" && acceptPin != AcceptNewPin {
		h, err := devicekey.ParseSPKIHash(acceptPin)
		if err != nil {
			return fmt.Errorf("node: accept pin: %w", err)
		}
		n.log.Warn("control plane key pinned as accepted at enrollment", "control", n.cfg.ControlAddr, "fingerprint", h.Fingerprint())
		return fp.Accept(h)
	}
	// look at the key: the handshake stops at it, nothing of ours is sent
	_, probeErr := n.control.EnrollStatus(ctx)
	h, seen := fp.Seen()
	if !seen {
		return fmt.Errorf("node: control plane not reachable: %w", probeErr)
	}
	if acceptPin == AcceptNewPin {
		n.log.Warn("control plane key pinned on first use, unseen by a person", "control", n.cfg.ControlAddr, "fingerprint", h.Fingerprint())
		return fp.Accept(h)
	}
	return &PinUnconfirmedError{Fingerprint: h.Fingerprint()}
}

// Enroll submits the enrollment request and returns the control plane's
// answer. It is idempotent. acceptPin: see confirmPin.
func (n *Node) Enroll(ctx context.Context, name, acceptPin string) (api.EnrollStatus, error) {
	if err := n.confirmPin(ctx, acceptPin); err != nil {
		return api.EnrollStatus{}, err
	}
	if name == "" {
		name = n.cfg.Name
	}
	host, _ := os.Hostname()
	st, err := n.control.Enroll(ctx, api.EnrollRequest{
		Name:          name,
		Hostname:      host,
		Platform:      runtime.GOOS,
		KeyKind:       n.key.Kind(),
		HardwareBound: n.key.HardwareBound(),
		Roles:         n.cfg.Roles,
		Prefixes:      n.cfg.Prefixes,
		PublicAddr:    n.cfg.PublicAddr,
	})
	if err != nil {
		n.mu.Lock()
		n.status.EnrollmentError = err.Error()
		n.mu.Unlock()
		return st, err
	}
	n.applyEnrollStatus(st)
	n.log.Info("enrollment", "status", st.Status, "node_id", st.NodeID, "fingerprint", st.Fingerprint)
	return st, nil
}

// Login starts a user login and returns the URL for the browser. The IdP
// host gets a bypass route while the overlay is up so a full-tunnel
// profile does not swallow the login.
func (n *Node) Login(ctx context.Context) (api.LoginStart, error) {
	if err := n.waitReady(ctx); err != nil {
		return api.LoginStart{}, err
	}
	st, err := n.control.LoginStart(ctx)
	if err != nil {
		return st, err
	}
	n.mu.Lock()
	s := n.sess
	n.mu.Unlock()
	if s != nil {
		if u, err := url.Parse(st.URL); err == nil && u.Hostname() != "" {
			if err := s.addBypassHost(ctx, u.Host); err != nil {
				n.log.Warn("bypass route for the identity provider", "host", u.Host, "err", err)
			}
		}
	}
	n.log.Info("login started", "flow", st.FlowID)
	return st, nil
}

// LoginWait polls a flow once, waiting up to wait.
func (n *Node) LoginWait(ctx context.Context, flowID string, wait time.Duration) (api.LoginStatus, error) {
	st, err := n.control.LoginStatus(ctx, flowID, wait)
	if err == nil && st.Status == "done" && st.Session != nil {
		n.log.Info("login completed", "subject", st.Session.Subject, "username", st.Session.Username, "groups", st.Session.Groups, "expires_at", st.Session.ExpiresAt)
		n.mu.Lock()
		if s := n.sess; s != nil && s.spoke != nil {
			s.spoke.retryNow()
		}
		n.mu.Unlock()
	}
	return st, err
}

// Logout ends the user session at the control plane.
func (n *Node) Logout(ctx context.Context) error {
	if err := n.control.Logout(ctx); err != nil {
		return err
	}
	n.log.Info("logged out")
	return nil
}

// Profiles lists the available profile names.
func (n *Node) Profiles() ([]string, error) {
	ps, err := profile.LoadDir(n.cfg.ProfilesDir)
	if err != nil {
		return nil, err
	}
	names := []string{"full"}
	for _, p := range ps {
		if p.Name != "full" {
			names = append(names, p.Name)
		}
	}
	return names, nil
}

func (n *Node) loadProfile(name string) (*profile.Profile, error) {
	if name == "" || name == "full" {
		return profile.Full(), nil
	}
	ps, err := profile.LoadDir(n.cfg.ProfilesDir)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}
	for _, p := range ps {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("unknown profile %q", name)
}

// waitReady makes sure the node is approved and holds a snapshot. The
// control loop learns about an approval within a few seconds; an `up` right
// after the admin clicked should not fail on that race, so this refreshes
// the enrollment state and waits briefly for the first snapshot.
func (n *Node) waitReady(ctx context.Context) error {
	n.mu.Lock()
	st := n.status.Enrollment
	n.mu.Unlock()
	if st != "approved" {
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		es, err := n.control.EnrollStatus(sctx)
		cancel()
		if err != nil {
			return fmt.Errorf("node: control plane: %w", err)
		}
		n.applyEnrollStatus(es)
		if es.Status != "approved" {
			return fmt.Errorf("node: not approved by the control plane (enrollment: %s); run `boundgatectl enroll` and ask an admin to confirm and sign %s", es.Status, n.spki.Fingerprint())
		}
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		if s := n.holder.Load(); s != nil && s.Self.ID != "" && !n.holder.Stale(time.Now()) {
			return nil
		}
		n.mu.Lock()
		bindErr := n.status.BindingError
		n.mu.Unlock()
		if bindErr != "" {
			return fmt.Errorf("node: own binding does not verify against the pinned admin keys: %s", bindErr)
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return errors.New("node: no current registry snapshot; is the control plane reachable? try again in a moment")
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ErrAlreadyUp is returned by Up while the overlay is up.
var ErrAlreadyUp = errors.New("node: overlay is already up; run down first")

// Up brings the overlay up: TUN, address, hub listener and/or hub links,
// routes. It returns once the local side is configured; hub links connect
// in the background (see Status).
func (n *Node) Up(ctx context.Context, profileName string) error {
	if err := n.waitReady(ctx); err != nil {
		return err
	}
	n.mu.Lock()
	if n.sess != nil {
		n.mu.Unlock()
		return ErrAlreadyUp
	}
	snap := n.holder.Load()
	if snap == nil || snap.Self.ID == "" || n.holder.Stale(time.Now()) {
		n.mu.Unlock()
		return errors.New("node: no current registry snapshot; is the control plane reachable? try again in a moment")
	}
	if profileName == "" {
		profileName = n.cfg.Profile // `up` without a profile means the configured one, not "full"
	}
	prof, err := n.loadProfile(profileName)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	s := newSession(n, snap, prof)
	n.sess = s
	n.status.State, n.status.LastError, n.status.Profile = StateStarting, "", prof.Name
	n.mu.Unlock()

	err = s.apply(ctx)
	// the routes changed (at least the bypass route to the control plane):
	// connections made before would wait on a path that is gone
	n.control.Reconnect()
	if err != nil {
		s.teardown()
		n.control.Reconnect()
		n.mu.Lock()
		if n.sess == s {
			n.sess = nil
		}
		n.status.State, n.status.LastError, n.status.Profile = StateDown, err.Error(), ""
		n.mu.Unlock()
		return err
	}
	n.mu.Lock()
	n.status.State = StateUp
	n.status.OverlayIP = s.self.OverlayIP.String()
	n.status.Roles = s.self.Roles
	n.status.Prefixes = nil
	for _, p := range s.self.Prefixes {
		n.status.Prefixes = append(n.status.Prefixes, p.Prefix.String()+" ("+string(p.Mode)+")")
	}
	n.status.Since = s.since
	n.status.LastClose = ""
	n.mu.Unlock()
	go n.watch(s)
	return nil
}

// Down tears the overlay down.
func (n *Node) Down(reason string) {
	n.mu.Lock()
	s := n.sess
	n.mu.Unlock()
	if s == nil {
		return
	}
	if reason == "" {
		reason = "down by user"
	}
	s.close(reason)
	<-s.done
}

// Close tears down on shutdown.
func (n *Node) Close() {
	n.Down("node shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	n.ship.flush(ctx)
	cancel()
	n.control.Close()
	if c, ok := n.key.(io.Closer); ok {
		c.Close() // a TPM key unloads itself
	}
}

func (n *Node) watch(s *session) {
	<-s.done
	n.control.Reconnect() // the bypass routes are gone
	n.mu.Lock()
	if n.sess == s {
		n.sess = nil
		n.status.State = StateDown
		n.status.LastClose = s.reason
		n.status.Profile, n.status.OverlayIP, n.status.Roles, n.status.Prefixes, n.status.Hubs, n.status.Routes, n.status.Tunnels = "", "", nil, nil, nil, nil, 0
	}
	n.mu.Unlock()
	n.log.Info("overlay down", "reason", s.reason)
}

// session is one "up" period: everything apply created, so teardown can
// undo it in reverse order.
type session struct {
	n       *Node
	ctx     context.Context
	cancel  context.CancelFunc
	profile *profile.Profile
	self    registry.Node
	pool    netip.Prefix
	isHub   bool

	dev    tun.Device
	ifname string
	dp     *dataplane
	srv    *transport.Server
	spoke  *spokeManager
	paths  *pathManager // spokes, unless no_paths
	flows  *flow.Table

	tmu     sync.Mutex
	tunnels map[string]*tunnelStats // hub: accepted tunnels, for reports

	mu        sync.Mutex
	bypass    map[netip.Addr]bool
	peerRoute map[netip.Prefix]int // hub: kernel routes for peer prefixes
	poolRoute bool
	nat       bool

	since  time.Time
	done   chan struct{}
	once   sync.Once
	reason string
}

func newSession(n *Node, snap *registry.Snapshot, prof *profile.Profile) *session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{
		n: n, ctx: ctx, cancel: cancel, profile: prof, self: snap.Self, pool: snap.Pool.Masked(),
		isHub:  snap.Self.IsHub() || registry.HasRole(snap.Self.Roles, registry.RoleHub),
		bypass: make(map[netip.Addr]bool), peerRoute: make(map[netip.Prefix]int), done: make(chan struct{}),
		tunnels: make(map[string]*tunnelStats),
	}
	s.flows = flow.New(flow.Timeouts{}, s.onFlowEvent)
	return s
}

func (s *session) apply(ctx context.Context) error {
	n := s.n
	if err := s.addBypassHost(ctx, n.cfg.ControlAddr); err != nil {
		return err
	}
	if !s.isHub && !n.cfg.AllowOverlap {
		if l, bad := conflictWith(s.pool, localNets("")); bad && l.Prefix.Addr() != s.self.OverlayIP {
			return fmt.Errorf("the overlay pool %s: another interface of this machine already uses that range (usually a second VPN); routing it would take over that traffic. Disconnect the other VPN, move the overlay pool, or set allow_overlap: true", describeConflict(s.pool, l))
		}
	}
	dev, ifname, err := n.net.CreateTUN(n.cfg.TUNName, n.cfg.MTU)
	if err != nil {
		return err
	}
	s.dev, s.ifname = dev, ifname
	bits := 32
	if s.isHub {
		bits = s.pool.Bits() // the whole pool is "on link" for a hub
	}
	if err := n.net.SetAddress(ctx, ifname, netip.PrefixFrom(s.self.OverlayIP, bits), n.cfg.MTU); err != nil {
		return err
	}
	if !s.isHub {
		if err := n.net.AddRoute(ctx, s.pool, ifname); err != nil {
			return err
		}
		s.poolRoute = true
	}
	forwards := s.isHub || registry.HasRole(s.self.Roles, registry.RoleSubnetRouter) || registry.HasRole(s.self.Roles, registry.RoleExitNode)
	if forwards {
		if err := n.net.EnableForwarding(ctx); err != nil {
			return err
		}
	}
	if err := s.applyNAT(ctx); err != nil {
		return err
	}
	s.dp = newDataplane(dev, ifname, n.log)
	s.dp.s = s
	go s.flowSweeper()

	if s.isHub {
		var pc net.PacketConn
		var gen quic.ConnectionIDGenerator
		var tcpLn net.Listener
		if !n.cfg.NoTCPFallback {
			ln, err := net.Listen("tcp", n.cfg.Listen)
			if err != nil {
				return fmt.Errorf("hub tcp listener: %w", err)
			}
			tcpLn = ln
		}
		if m := n.cfg.BehindMux; m != nil {
			bc, err := mux.ListenBackend(n.cfg.Listen, m.Trusted)
			if err != nil {
				if tcpLn != nil {
					_ = tcpLn.Close()
				}
				return err
			}
			pc, gen = bc, mux.CIDGenerator{ID: m.ID}
			if tcpLn != nil && !m.NoProxyProtocol {
				tcpLn = &mux.ProxyListener{Listener: tcpLn, Trusted: m.Trusted}
			}
			n.log.Info("hub listens behind a mux", "addr", n.cfg.Listen, "id", m.ID, "trusted", m.Trusted, "proxy_protocol", tcpLn != nil && !m.NoProxyProtocol)
		}
		srv, err := transport.NewServer(transport.ServerConfig{
			PacketConn:      pc,
			ConnIDGenerator: gen,
			TCPListener:     tcpLn,
			Addr:            n.cfg.Listen,
			TLS:             transport.ServerTLSConfig(n.cert, n.holder),
			Lookup:          n.holder,
			Template:        transport.HubTemplate,
			IdleTimeout:     30 * time.Second,
			KeepAlive:       10 * time.Second,
			Logger:          n.log,
		}, &hubService{s: s})
		if err != nil {
			if tcpLn != nil {
				_ = tcpLn.Close()
			}
			return err
		}
		if err := srv.Listen(); err != nil {
			if tcpLn != nil {
				_ = tcpLn.Close()
			}
			return err
		}
		s.srv = srv
		// tell the control plane that any tunnel it still lists for us is gone
		n.ship.add(api.ShippedEvent{TS: time.Now(), Stream: api.ShipStreamTunnel, Message: "reset"})
		go s.sessionWatch()
		go func() {
			if err := srv.Serve(s.ctx); err != nil {
				n.log.Error("hub listener failed", "err", err)
				s.close("hub listener failed: " + err.Error())
			}
		}()
		n.log.Info("hub listening", "udp", srv.LocalAddr().String(), "tcp_fallback", tcpLn != nil, "overlay_ip", s.self.OverlayIP, "public_addr", n.cfg.PublicAddr)
	}
	hubs := n.holder.Load().Hubs()
	if !s.isHub {
		s.spoke = newSpokeManager(s)
		if !n.cfg.NoPaths {
			s.paths = newPathManager(s)
			go s.paths.run(s.ctx)
			if n.cfg.PathsListen != "" {
				if err := s.paths.listenDirect(s.ctx, n.cfg.PathsListen); err != nil {
					return err
				}
			}
			// whatever tunnels the control plane still lists as accepted here are gone
			n.ship.add(api.ShippedEvent{TS: time.Now(), Stream: api.ShipStreamTunnel, Message: "reset"})
			go s.sessionWatch()
		}
		s.spoke.sync(hubs)
		if len(hubs) == 0 {
			n.log.Warn("registry lists no hubs; waiting for one to be approved")
		}
	}
	go func() {
		if err := s.dp.RunTUNReader(s.ctx); err != nil {
			n.log.Error("tun reader failed", "err", err)
			s.close("tun reader failed: " + err.Error())
		}
	}()
	s.since = time.Now()
	n.log.Info("overlay up", "profile", s.profile.Name, "overlay_ip", s.self.OverlayIP, "roles", s.self.Roles, "hub", s.isHub, "hubs", len(hubs))
	return nil
}

// applyNAT installs masquerade rules for the node's snat prefixes.
func (s *session) applyNAT(ctx context.Context) error {
	var dsts []netip.Prefix
	for _, p := range s.self.Prefixes {
		if p.Mode == registry.ModeSNAT {
			dsts = append(dsts, p.Prefix)
		}
	}
	if len(dsts) == 0 && !s.nat {
		return nil
	}
	if err := s.n.net.SetNAT(ctx, s.pool, dsts, s.ifname); err != nil {
		return err
	}
	s.nat = len(dsts) > 0
	return nil
}

// applyDiff reacts to a new snapshot while up.
func (s *session) applyDiff(diff registry.Diff, snap *registry.Snapshot) {
	n := s.n
	if snap.Self.ID == "" {
		s.close("node no longer approved by the control plane")
		return
	}
	if s.srv != nil {
		for _, id := range diff.RemovedPeers {
			if c := s.srv.CloseDevice(id, transport.ErrCodeRevoked, "peer unenrolled or reconfigured"); c > 0 {
				n.log.Info("peer tunnels closed", "node", id, "closed", c)
			}
		}
	}
	if s.paths != nil {
		s.paths.rebuild(snap)
		for _, id := range diff.RemovedPeers {
			s.paths.closePeer(id)
		}
	}
	for _, id := range diff.RemovedPeers {
		s.flows.CloseWhere(func(e *flow.Entry) bool { return e.Origin.Principal == id }, "peer removed")
	}
	if diff.PoliciesChanged || diff.SessionsChanged || len(diff.RemovedPeers) > 0 {
		if c := s.flows.Reevaluate(s.decide); c > 0 {
			n.log.Info("flows closed by policy or session change", "closed", c)
		}
	}
	if diff.SelfChanged {
		old := s.self
		s.self = snap.Self
		s.pool = snap.Pool.Masked()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.applyNAT(ctx); err != nil {
			n.log.Error("reapply nat", "err", err)
		}
		cancel()
		if old.OverlayIP != snap.Self.OverlayIP || !equalRoles(old.Roles, snap.Self.Roles) {
			n.log.Warn("own overlay address or roles changed; restart the overlay (down/up) to apply", "old_ip", old.OverlayIP, "new_ip", snap.Self.OverlayIP)
		}
	}
	if s.spoke != nil && diff.HubsChanged {
		s.spoke.sync(snap.Hubs())
	}
	if s.spoke != nil && diff.SessionsChanged {
		s.spoke.retryNow()
	}
	if (s.srv != nil || s.paths != nil) && diff.SessionsChanged {
		s.enforceSessions(snap)
	}
	n.publishStatus()
}

// enforceSessions closes tunnels of interactive peers without a valid user
// session (revoked, logged out, expired). Runs on every snapshot with
// session changes and periodically, so expiry is enforced even without a
// snapshot bump.
func (s *session) enforceSessions(snap *registry.Snapshot) {
	if s.paths != nil {
		s.paths.enforceSessions(snap)
	}
	if s.srv == nil || snap == nil {
		return
	}
	now := time.Now()
	for _, id := range s.srv.ActiveDevices() {
		p, ok := snap.Peer(id)
		if !ok || !p.NeedsSession() {
			continue
		}
		if _, ok := snap.SessionFor(id, now); !ok {
			if c := s.srv.CloseDevice(id, transport.ErrCodeSessionExpired, "user session ended"); c > 0 {
				s.n.log.Info("peer tunnels closed: no user session", "peer", p.Name, "node", id, "closed", c)
			}
		}
	}
}

// sessionWatch enforces session expiry on a hub every 10 s and reports
// tunnel counters to the control plane every 30 s.
func (s *session) sessionWatch() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	tick := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.enforceSessions(s.n.holder.Load())
			if tick++; tick%3 == 0 {
				s.reportTunnels()
			}
		}
	}
}

func equalRoles(a, b []registry.Role) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		as[i], bs[i] = string(a[i]), string(b[i])
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// addBypassHost pins a host route for hostport's address outside the overlay.
func (s *session) addBypassHost(ctx context.Context, hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	ip, err := resolveHost(ctx, host)
	if err != nil {
		return err
	}
	return s.addBypass(ip)
}

// addBypass pins a host route (idempotent within the session).
func (s *session) addBypass(ip netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bypass[ip] || s.pool.Contains(ip) || ip.IsLoopback() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.n.net.AddBypass(ctx, ip); err != nil {
		return err
	}
	s.bypass[ip] = true
	return nil
}

// addPeerRoute installs a kernel route for a peer prefix via the TUN so the
// hub's host stack (and its LAN) can reach it. Counted per announcer.
func (s *session) addPeerRoute(p netip.Prefix) {
	p = p.Masked()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerRoute[p]++
	if s.peerRoute[p] > 1 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, q := range splitDefault(p) {
		if err := s.n.net.AddRoute(ctx, q, s.ifname); err != nil {
			s.n.log.Warn("peer route add", "prefix", q, "err", err)
		}
	}
}

func (s *session) delPeerRoute(p netip.Prefix) {
	p = p.Masked()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerRoute[p]--
	if s.peerRoute[p] > 0 {
		return
	}
	delete(s.peerRoute, p)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, q := range splitDefault(p) {
		_ = s.n.net.DelRoute(ctx, q, s.ifname)
	}
}

func (s *session) close(reason string) {
	s.once.Do(func() {
		s.reason = reason
		s.teardown()
		close(s.done)
	})
}

// teardown undoes everything apply did, in reverse order. Safe to call on a
// partially built session.
func (s *session) teardown() {
	n := s.n
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.cancel() // stops the hub listener (closes tunnels), TUN reader and hub links
	s.flows.CloseWhere(func(*flow.Entry) bool { return true }, "overlay down")
	if s.paths != nil {
		s.paths.stop()
	}
	if s.spoke != nil {
		s.spoke.stop()
		s.spoke.mu.Lock()
		for p := range s.spoke.installed {
			_ = n.net.DelRoute(ctx, p, s.ifname)
		}
		s.spoke.installed = map[netip.Prefix]bool{}
		s.spoke.mu.Unlock()
	}
	s.mu.Lock()
	for p := range s.peerRoute {
		for _, q := range splitDefault(p) {
			_ = n.net.DelRoute(ctx, q, s.ifname)
		}
	}
	s.peerRoute = map[netip.Prefix]int{}
	if s.nat {
		_ = n.net.SetNAT(ctx, s.pool, nil, s.ifname)
		s.nat = false
	}
	if s.poolRoute {
		_ = n.net.DelRoute(ctx, s.pool, s.ifname)
		s.poolRoute = false
	}
	if s.dev != nil {
		_ = s.dev.Close()
		s.dev = nil
	}
	for ip := range s.bypass {
		_ = n.net.DelBypass(ctx, ip)
	}
	s.bypass = map[netip.Addr]bool{}
	s.mu.Unlock()
}

// autoKeyKind resolves key kind "auto"; enclave says whether this machine has
// a usable Secure Enclave. A node that is bound to a control plane keeps the
// identity it enrolled with: it must not come back from an update as somebody
// else. Everywhere else the hardware wins: a fresh state directory, and also
// a software key left over from earlier that no control plane knows this node
// by any more (no pinned control plane: never enrolled, or forgotten).
func autoKeyKind(cfg Config, enclave bool) string {
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(cfg.StateDir, name)); return err == nil }
	switch {
	case exists("device.sekey"):
		return sekey.Kind
	case !enclave:
		return "softkey"
	case !exists("device.key"):
		return sekey.Kind
	case cfg.ControlPin == "" && !exists("control.pin"):
		cfg.Log.Warn("a software key from earlier exists, but this node is not bound to a control plane: it gets a key in the Secure Enclave instead. device.key is left where it is and no longer used")
		return sekey.Kind
	default:
		return "softkey"
	}
}

// keyWarning says, for the person in front of the machine, what is wrong with
// a software key on a machine that could do better, or cannot.
func keyWarning(kind string, enclave bool) string {
	if runtime.GOOS != "darwin" || kind != "softkey" {
		return ""
	}
	if enclave {
		return "This Mac's identity is a software key: a file that anyone with administrator rights, a backup or malware can copy to another machine. This Mac has a Secure Enclave; the node kept the software key it enrolled with. A new identity in the Secure Enclave cannot be copied (the Mac then has to be approved again)."
	}
	return "This Mac's identity is a software key: a file that anyone with administrator rights, a backup or malware can copy to another machine. No usable Secure Enclave was found (Intel Macs without a T2 chip have none, or the helper boundgate-sekey is missing from the app), so it cannot be bound to the hardware."
}
