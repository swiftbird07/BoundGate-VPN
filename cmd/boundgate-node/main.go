// boundgate-node is the privileged daemon of every BoundGate participant:
// endpoint, subnet router, hub or exit node, decided by the roles an admin
// granted. Control it with boundgatectl over the local socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/update"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/version"
)

type config struct {
	Name     string `yaml:"name"`
	StateDir string `yaml:"state_dir"`
	KeyKind  string `yaml:"key_kind"`
	// TPMDevice: for key_kind tpm2; default /dev/tpmrm0, or unix:PATH / tcp:HOST:PORT (swtpm)
	TPMDevice string `yaml:"tpm_device"`
	// SEKeyHelper: for key_kind secure-enclave; default boundgate-sekey next to this executable
	SEKeyHelper string `yaml:"sekey_helper"`
	Control     struct {
		Addr       string `yaml:"addr"`
		ServerName string `yaml:"server_name"`
		// Pin is the hex SPKI hash of the control plane's node-channel key;
		// empty = trust on first use (stored in state_dir/control.pin).
		Pin string `yaml:"pin"`
		// SignersGenesis is the hex SHA-256 of the genesis admin key list
		// (shown in the admin UI); empty = pin the signed list on first use.
		SignersGenesis string `yaml:"signers_genesis"`
	} `yaml:"control"`
	Roles      []string          `yaml:"roles"`
	Prefixes   []registry.Prefix `yaml:"prefixes"`
	PublicAddr string            `yaml:"public_addr"`
	Listen     string            `yaml:"listen"`
	BehindMux  *struct {
		ID              int      `yaml:"id"`                // 1..255, first byte of this hub's QUIC connection IDs
		Trusted         []string `yaml:"trusted"`           // where the mux delivers from, e.g. [127.0.0.1]
		NoProxyProtocol bool     `yaml:"no_proxy_protocol"` // the TCP front sends no PROXY v2 header
	} `yaml:"behind_mux"`
	TCPFallback *bool         `yaml:"tcp_fallback"` // default true: hubs serve the tunnel on TCP too, spokes fall back to it
	Transport   string        `yaml:"transport"`    // spoke: auto (default) | quic | tcp
	QUICRetry   time.Duration `yaml:"quic_retry"`   // spoke on TCP: how often to try QUIC again, default 2m
	Relay       *bool         `yaml:"relay"`        // hub, default true: relay between spokes that cannot reach each other
	// DNS (hub, default empty): resolvers this hub offers its spokes when the
	// tunnel opens. The apps (Android, iOS) then resolve through them only,
	// through the tunnel; the hub lets DNS to them through (port 53) for every
	// peer, also before the sign-in and whatever the policies allow. Daemons
	// keep the system's resolver.
	DNS []netip.Addr `yaml:"dns"`
	// Resolver (spoke, default hub): what to do with the resolvers the
	// primary hub offers. `hub` sends this host's names to them while the
	// overlay is up (Linux: every DNS query of the host and its containers
	// is redirected with nftables; /etc/resolv.conf is not touched), `system`
	// leaves the host's resolver alone. A node that resolves outside the
	// tunnel cannot be matched by a dynamic access list by name, and plain
	// HTTP reaches the hub as a bare address (docs/ACL.md).
	Resolver string `yaml:"resolver"`
	// DNSLearnFrom (enforcing node, default: dns): the resolvers whose
	// answers this node believes. It reads the answers it forwards and
	// remembers, per peer, which addresses a name resolved to, so that a
	// dynamic access list also matches a connection to those addresses
	// (docs/ACL.md). An answer from any other resolver is forwarded but not
	// believed: a device must not be able to name an address itself.
	DNSLearnFrom []netip.Addr `yaml:"dns_learn_from"`
	Paths        struct {
		Disabled bool          `yaml:"disabled"` // spoke: everything stays on the hub path
		Listen   string        `yaml:"listen"`   // spoke: UDP address peers can dial (announce it with public_addr)
		Idle     time.Duration `yaml:"idle"`     // close a path nothing used for this long, default 5m
	} `yaml:"paths"`
	AutoUp       bool              `yaml:"auto_up"`
	Profile      string            `yaml:"profile"`
	ProfilesDir  string            `yaml:"profiles_dir"`
	Socket       string            `yaml:"socket"`
	SocketGroup  string            `yaml:"socket_group"` // group that may use the socket next to root (macOS app: admin)
	SocketUsers  []string          `yaml:"socket_users"` // Windows: accounts that may use it too (install.ps1: the installing account)
	TUNName      string            `yaml:"tun_name"`
	HubAddrs     map[string]string `yaml:"hub_addrs"`     // dial override per hub name or public_addr
	AllowOverlap bool              `yaml:"allow_overlap"` // route networks this machine already lives in (overlap guard off)
	// ReplyViaArrival (Linux, not on hubs): connections that come in from
	// outside (a port forward on the router) are answered the way they came,
	// while everything this host and its containers start goes through the
	// tunnel, e.g. to an exit node whose policies decide (docs/ARRIVAL.md).
	ReplyViaArrival bool `yaml:"reply_via_arrival"`
	// PowerSave: a quiet node sends nothing (no keep-alives, the snapshot
	// polled every 10 min instead of a long-poll), for a laptop on battery.
	// Peers reach it only after it sent something itself (docs/POWER.md).
	PowerSave bool `yaml:"power_save"`
	// Privsep (Linux): the control channel, the tunnels and every packet run
	// in a worker process as this user (name, or uid[:gid]); this process
	// keeps the device key and the host's network and answers the worker
	// only what its rules allow (docs/PRIVSEP.md). Empty: one process.
	Privsep struct {
		User string `yaml:"user"`
		// Sandbox: the worker confines itself before it reads anything from
		// the network (seccomp, Landlock; internal/sandbox). enforce (the
		// default), audit (system calls off the list are logged by the
		// kernel, not refused) or off.
		Sandbox string `yaml:"sandbox"`
	} `yaml:"privsep"`
	MTU       int    `yaml:"mtu"`
	LogDir    string `yaml:"log_dir"`
	LogStdout bool   `yaml:"log_stdout"`
	// Update: release checks (and, from the app bundle, installation).
	// Release builds check by default; `check: false` turns that off.
	Update struct {
		Check     *bool         `yaml:"check"`
		Source    string        `yaml:"source"`     // github (default) or gitea; a url alone means gitea
		URL       string        `yaml:"url"`        // the Gitea instance; for github only to point at another host
		Repo      string        `yaml:"repo"`       // owner/name, default the project's
		TokenFile string        `yaml:"token_file"` // gitea: read token for instances without anonymous access; default update.token in state_dir
		Interval  time.Duration `yaml:"interval"`   // default 6h
	} `yaml:"update"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == workerArg {
		os.Exit(runWorker())
	}
	if handled, err := serviceCommand(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "boundgate-node:", err)
			os.Exit(1)
		}
		return
	}
	cfgPath := flag.String("config", "", "configuration file (default: node.yaml next to the executable, else "+defaults.config+")")
	repair := flag.Bool("repair", false, "undo network changes a node left on this host (the resolver first, then routes and NAT) and exit; needs root, needs no daemon")
	flag.Parse()
	if *cfgPath == "" {
		*cfgPath = defaultConfigPath()
	}
	if *repair {
		if err := repairHost(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "boundgate-node:", err)
			os.Exit(1)
		}
		return
	}
	if err := runMain(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		os.Exit(1)
	}
}

// defaultConfigPath: node.yaml next to the executable (a package, the
// Windows zip), in a macOS app bundle's Contents/Resources, else the
// platform's default.
func defaultConfigPath() string {
	p := defaults.config
	if exe, err := os.Executable(); err == nil {
		for _, c := range []string{filepath.Join(filepath.Dir(exe), "node.yaml"), filepath.Join(filepath.Dir(exe), "..", "Resources", "node.yaml")} {
			if fileExists(c) {
				return c
			}
		}
	}
	return p
}

// run is the daemon until ctx ends: a signal on Unix, the service manager on
// Windows.
func run(ctx context.Context, cfgPath string) error {
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	cfg, err := parseConfig(b)
	if err != nil {
		return err
	}
	if cfg.Privsep.User != "" {
		return runPrivileged(ctx, b, cfg)
	}
	return runWith(ctx, cfg, nil)
}

// separated is what a worker of privilege separation brings to runWith:
// the key and the host's network through the parent, and the socket the
// parent made (internal/privsep).
type separated struct {
	key     devicekey.DeviceKey
	net     netcfg.Configurator
	anchors anchors.Anchors
	socket  *os.File
	uid     int
	// sandbox is what confines the worker, in words; incomplete says what
	// of it this machine does not have
	sandbox    string
	incomplete []string
	// forget asks the privileged parent to delete the node's identity: the
	// files are its own, not the worker's (docs/PRIVSEP.md).
	forget func(newIdentity bool) error
}

// parseConfig reads the configuration and fills in the defaults.
func parseConfig(b []byte) (config, error) {
	var cfg config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	if cfg.StateDir == "" {
		cfg.StateDir = defaults.stateDir
	}
	if cfg.ProfilesDir == "" {
		cfg.ProfilesDir = defaults.profilesDir
	}
	if cfg.Socket == "" {
		cfg.Socket = ipc.DefaultSocket()
	}
	if cfg.LogDir == "" {
		cfg.LogDir = defaults.logDir // Windows: a service has no console to write to
	}
	return cfg, nil
}

// runWith is the daemon with its configuration; sep is set in the worker of
// privilege separation.
func runWith(ctx context.Context, cfg config, sep *separated) error {
	logs, err := logging.Open(logging.Options{Dir: cfg.LogDir, Stdout: cfg.LogStdout || cfg.LogDir == "", Component: "node"})
	if err != nil {
		return err
	}
	defer logs.Close()
	slog.SetDefault(logs.System)
	logging.ThrottleStdLog(logs.System)

	// A configuration file that names the control plane is final. Without
	// one, the user decides (boundgatectl configure, or the app): setup mode
	// until then, and `reset` leads back here.
	fromFile := cfg.Control.Addr != ""
	if underLaunchd() {
		// also in setup mode, where no node runs
		idle := func() bool { n := running.Load(); return n == nil || n.Status().State == node.StateDown }
		go restartWhenReplaced(ctx, logs.System, idle, 15*time.Second)
	}
	// one updater for the life of the daemon: with a node running and in
	// setup mode, where an update needs no control plane
	upd := newUpdater(cfg, logs.System, func() bool { n := running.Load(); return n == nil || n.Status().State == node.StateDown })
	if upd != nil {
		go upd.Run(ctx)
	}
	// Several networks are for a device a person uses: a server's control
	// plane stands in its configuration file, and a separated node may
	// write exactly one state directory (docs/PRIVSEP.md). Both of them run
	// the one network they are given, and the network endpoints say so.
	var nets *networks
	single := ""
	switch {
	case fromFile:
		single = "the control plane of this node stands in its configuration file (control.addr)"
	case sep != nil:
		single = "this node is separated: its sandbox opens one state directory, so it holds one network (docs/PRIVSEP.md)"
	default:
		nets = &networks{root: cfg.StateDir}
	}
	for ctx.Err() == nil {
		cur := current{
			stateDir:     cfg.StateDir,
			settingsPath: filepath.Join(cfg.StateDir, "settings.json"),
			netStatePath: filepath.Join(cfg.StateDir, "netstate.json"),
			single:       single,
		}
		local := ipc.Settings{ControlAddr: cfg.Control.Addr, ControlServerName: cfg.Control.ServerName, Name: cfg.Name}
		switch {
		case nets != nil:
			n, ok, err := nets.reload()
			if err != nil {
				return err
			}
			if !ok {
				logs.System.Info("no network configured; waiting for `boundgatectl configure`", "socket", cfg.Socket)
				if err := serveSetup(ctx, cfg, upd, sep, nets); err != nil {
					return err
				}
				continue
			}
			cur.network(n, cfg.StateDir, nets)
			local.ControlAddr, local.ControlServerName = n.ControlAddr, n.ControlServerName
			if n.NodeName != "" {
				local.Name = n.NodeName
			}
			cur.upWith = nets.takeProfile()
		case !fromFile:
			s, err := ipc.LoadSettings(cur.settingsPath)
			if err != nil {
				return err
			}
			if s.ControlAddr == "" {
				logs.System.Info("no control plane configured; waiting for `boundgatectl configure`", "socket", cfg.Socket)
				if err := serveSetup(ctx, cfg, upd, sep, nil); err != nil {
					return err
				}
				continue
			}
			local.ControlAddr, local.ControlServerName = s.ControlAddr, s.ControlServerName
			if s.Name != "" {
				local.Name = s.Name
			}
		}
		err := runNode(ctx, cfg, local, logs, fromFile, cur, upd, sep)
		switch {
		case errors.Is(err, ipc.ErrSwitch):
			// the node is down and its routes with it; the next turn of the
			// loop runs whatever network is current now
			logs.System.Info("leaving this network", "network", cur.name)
			continue
		case errors.Is(err, ipc.ErrReset):
			switch {
			case sep != nil:
				// the key the privileged parent holds is open; the new one
				// comes with a new process, which the service manager starts
				logs.System.Warn("the node gave up its identity; ending so the service starts again with a new key")
				return nil
			case fromFile:
				logs.System.Warn("the node gave up its identity; it enrolls with the configured control plane again", "control", cfg.Control.Addr)
			case cur.id != "":
				logs.System.Warn("network forgotten", "network", cur.name)
			default:
				logs.System.Warn("control plane forgotten; back to setup mode")
			}
			continue
		}
		return err
	}
	return nil
}

// current is the network runNode runs: where its state lives, how it is
// called, and -- right after a switch -- the profile it should come up in.
type current struct {
	stateDir     string
	settingsPath string
	// netStatePath is the cleanup journal, which stays one for the daemon:
	// after a crash the next start removes the leftovers of whatever
	// network was running (docs/SECURITY.md R143).
	netStatePath string
	id, name     string
	// upWith: bring the overlay up in this profile as soon as the control
	// plane approves. Someone who picked "Work - Full" has said enough.
	upWith string
	// nets is the daemon's list of networks for the socket; single says why
	// there is none to manage.
	nets   ipc.Networker
	single string
}

// network points cur at one of several networks: its own state directory,
// so key, pin, admin keys and enrollment are the network's own (R142).
func (cur *current) network(n ipc.Network, root string, nets ipc.Networker) {
	cur.stateDir = n.Path(root)
	cur.settingsPath = filepath.Join(cur.stateDir, "settings.json")
	cur.id, cur.name = n.ID, n.Name
	cur.nets, cur.single = nets, ""
}

// serveSetup waits in setup mode: nobody has chosen a control plane yet.
// With nets the socket can also list and add networks there, so an app sets
// up its first network the same way it adds a second one later.
func serveSetup(ctx context.Context, cfg config, upd *update.Service, sep *separated, nets *networks) error {
	host, _ := os.Hostname()
	access := ipc.Options{Group: cfg.SocketGroup, Users: cfg.SocketUsers}
	if sep != nil {
		access.Listener = sep.socket
	}
	save := func(s ipc.Settings) error { return ipc.SaveSettings(filepath.Join(cfg.StateDir, "settings.json"), s) }
	if nets != nil {
		access.Nets = nets
		// `configure` names the first network after its control plane; a
		// client that knows about networks sends a name with it
		save = func(s ipc.Settings) error { _, err := nets.Add("", s, true, ""); return err }
	}
	_, err := ipc.ServeSetup(ctx, cfg.Socket, access, node.Status{NodeName: host, Enrollment: "unknown"}, upd, save)
	return err
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func runNode(ctx context.Context, cfg config, local ipc.Settings, logs *logging.Streams, fromFile bool, cur current, upd *update.Service, sep *separated) error {
	var behindMux *node.BehindMux
	if m := cfg.BehindMux; m != nil {
		if m.ID < 1 || m.ID > 255 {
			return errors.New("config: behind_mux.id must be 1..255")
		}
		trusted, err := mux.ParseTrusted(m.Trusted)
		if err != nil || len(trusted) == 0 {
			return fmt.Errorf("config: behind_mux.trusted: %v", err)
		}
		behindMux = &node.BehindMux{ID: byte(m.ID), Trusted: trusted, NoProxyProtocol: m.NoProxyProtocol}
	}
	nc := node.Config{
		Name:              local.Name,
		StateDir:          cur.stateDir,
		NetStatePath:      cur.netStatePath,
		NetworkID:         cur.id,
		NetworkName:       cur.name,
		KeyKind:           cfg.KeyKind,
		TPMDevice:         cfg.TPMDevice,
		SEKeyHelper:       cfg.SEKeyHelper,
		ControlAddr:       local.ControlAddr,
		ControlServerName: local.ControlServerName,
		ControlPin:        cfg.Control.Pin,
		SignersGenesis:    cfg.Control.SignersGenesis,
		Roles:             cfg.Roles,
		Prefixes:          cfg.Prefixes,
		PublicAddr:        cfg.PublicAddr,
		Listen:            cfg.Listen,
		BehindMux:         behindMux,
		NoTCPFallback:     cfg.TCPFallback != nil && !*cfg.TCPFallback,
		Transport:         cfg.Transport,
		QUICRetry:         cfg.QUICRetry,
		NoRelay:           cfg.Relay != nil && !*cfg.Relay,
		DNS:               cfg.DNS,
		DNSLearnFrom:      cfg.DNSLearnFrom,
		Resolver:          cfg.Resolver,
		NoPaths:           cfg.Paths.Disabled,
		PathsListen:       cfg.Paths.Listen,
		PathIdle:          cfg.Paths.Idle,
		AutoUp:            cfg.AutoUp,
		Profile:           cfg.Profile,
		ProfilesDir:       cfg.ProfilesDir,
		TUNName:           cfg.TUNName,
		HubAddrs:          cfg.HubAddrs,
		AllowOverlap:      cfg.AllowOverlap,
		ReplyViaArrival:   cfg.ReplyViaArrival,
		PowerSave:         cfg.PowerSave,
		MTU:               cfg.MTU,
		Log:               logs.System,
		FlowLog:           logs.Flow,
	}
	if sep != nil {
		nc.Key, nc.Net, nc.Anchors = sep.key, sep.net, sep.anchors
		nc.Separation = fmt.Sprintf("worker uid %d; key and host network in the privileged parent", sep.uid)
		nc.Sandbox = sep.sandbox
		if len(sep.incomplete) > 0 {
			logs.System.Warn("the worker's sandbox is incomplete", "sandbox", sep.sandbox)
		} else {
			logs.System.Info("the worker is confined", "sandbox", sep.sandbox)
		}
	}
	if cur.upWith != "" {
		// the user picked a network together with a profile: come up in it
		// as soon as the control plane approves, without a second request
		nc.AutoUp, nc.Profile = true, cur.upWith
	}
	n, err := node.New(nc)
	if err != nil {
		return err
	}
	// what a library writes about a refused packet says nothing by itself;
	// the node knows whose address it was (logging.ExplainStdLog)
	logging.ExplainStdLog(n.ExplainLibraryLine)
	defer logging.ExplainStdLog(nil)
	ctx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() { defer close(runDone); n.Run(ctx) }()
	defer func() {
		// Run ends before the control client closes: closing it under a
		// request that is just starting races inside quic-go's transport
		cancel()
		<-runDone
		n.Close()
	}()
	running.Store(n)
	defer running.Store(nil)
	opt := ipc.Options{Group: cfg.SocketGroup, Users: cfg.SocketUsers, Update: upd, Nets: cur.nets, SingleNetwork: cur.single}
	if sep != nil {
		opt.Listener = sep.socket
	}
	logs.System.Info("node ready", "socket", cfg.Socket, "control", local.ControlAddr, "auto_up", nc.AutoUp, "network", cur.name)
	opt.Reset = resetFunc(fromFile, sep, cur)
	return ipc.Serve(ctx, cfg.Socket, n, opt)
}

// resetFunc answers POST /v1/reset: forget the control plane — its address,
// its pinned key and the admin key list learned from it — and with
// newIdentity the device key as well, so the node comes back as a stranger
// (a software key that becomes a TPM or Secure Enclave key, or a key that was
// revoked).
//
// A node whose control plane stands in its configuration file keeps that
// address: forgetting it would mean nothing, the file names it again. Its
// identity it can still give up, and that is what a new key needs. Deleting
// the state directory by hand is not the way — under a running daemon it
// leaves the process writing into an unlinked directory.
func resetFunc(fromFile bool, sep *separated, cur current) func(bool) error {
	return func(newIdentity bool) error {
		if fromFile && !newIdentity {
			return errors.New("the control plane of this node stands in its configuration file (control.addr), so there is nothing to forget; `reset -new-identity` gives it a new device key for the same control plane")
		}
		if sep != nil {
			// the pin, the trust and the key files belong to the privileged
			// parent, in a state directory that is sticky: only it can
			if sep.forget == nil {
				return errors.New("this worker cannot ask its parent to give up the node's identity")
			}
			return sep.forget(newIdentity)
		}
		settingsPath := cur.settingsPath
		if fromFile {
			settingsPath = "" // there is none, and it is not ours to remove
		}
		// one of several networks: forgetting its control plane means
		// giving up that network, which is what removing it does
		if cur.nets != nil && !newIdentity {
			return cur.nets.Remove(cur.id)
		}
		return ipc.Forget(cur.stateDir, settingsPath, newIdentity)
	}
}

// running is the node of the current runNode, for restartWhenReplaced.
var running atomic.Pointer[node.Node]

// newUpdater builds the release checker. A build without release keys, or
// one that is not a release, still answers "what is the latest": it never
// offers to install.
func newUpdater(cfg config, log *slog.Logger, idle func() bool) *update.Service {
	keys, err := update.BuiltinKeys()
	if err != nil {
		log.Info("updates are off", "reason", err)
		return nil
	}
	u := cfg.Update
	interval := u.Interval
	if interval == 0 {
		interval = 6 * time.Hour
	}
	if (u.Check != nil && !*u.Check) || !version.IsRelease() {
		interval = 0 // no background checks; a manual check still works
	}
	src, err := update.ResolveSource(u.Source, u.URL, u.Repo)
	if err != nil {
		log.Warn("updates are off", "reason", err)
		return nil
	}
	tokenFile := u.TokenFile
	if tokenFile == "" {
		// the app's node.yaml is part of the signed bundle and cannot name a file:
		// a read token for an instance that wants a login goes here (root, 0600)
		tokenFile = filepath.Join(cfg.StateDir, "update.token")
	}
	s := &update.Service{Source: src, TokenFile: tokenFile, Keys: keys, Current: version.Version, Interval: interval,
		Idle: idle, WorkDir: filepath.Join(cfg.StateDir, "update"), Mac: update.MacApp{Run: update.SystemRun}, Log: log}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		s.Bundle, _ = update.BundleOf(exe)
	}
	return s
}
