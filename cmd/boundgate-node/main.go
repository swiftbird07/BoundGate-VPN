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

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
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
	// LoginPassthrough (hub, default empty): destinations an interactive node
	// may reach through this hub before its user has signed in, e.g. the
	// IdP and a DNS resolver. Only needed for Android's Always-on VPN with
	// "Block connections without VPN": there even the browser's way to the
	// IdP must go through the tunnel, which the hub otherwise refuses until
	// the sign-in (docs/ANDROID.md). Empty: no tunnel without a session.
	LoginPassthrough []netip.Prefix `yaml:"login_passthrough"`
	// DNS (hub, default empty): resolvers this hub offers its spokes when the
	// tunnel opens. The apps (Android, iOS) then resolve through them only,
	// through the tunnel; the hub lets DNS to them through (port 53) for every
	// peer, also before the sign-in and whatever the policies allow. Daemons
	// keep the system's resolver.
	DNS []netip.Addr `yaml:"dns"`
	Paths       struct {
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
	MTU          int               `yaml:"mtu"`
	LogDir       string            `yaml:"log_dir"`
	LogStdout    bool              `yaml:"log_stdout"`
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
	if handled, err := serviceCommand(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "boundgate-node:", err)
			os.Exit(1)
		}
		return
	}
	cfgPath := flag.String("config", "", "configuration file (default: node.yaml next to the executable, else "+defaults.config+")")
	flag.Parse()
	if *cfgPath == "" {
		*cfgPath = defaultConfigPath()
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
	var cfg config
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("config: %w", err)
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
	logs, err := logging.Open(logging.Options{Dir: cfg.LogDir, Stdout: cfg.LogStdout || cfg.LogDir == "", Component: "node"})
	if err != nil {
		return err
	}
	defer logs.Close()
	slog.SetDefault(logs.System)

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
	settingsPath := filepath.Join(cfg.StateDir, "settings.json")
	for ctx.Err() == nil {
		local := ipc.Settings{ControlAddr: cfg.Control.Addr, ControlServerName: cfg.Control.ServerName, Name: cfg.Name}
		if !fromFile {
			s, err := ipc.LoadSettings(settingsPath)
			if err != nil {
				return err
			}
			if s.ControlAddr == "" {
				logs.System.Info("no control plane configured; waiting for `boundgatectl configure`", "socket", cfg.Socket)
				host, _ := os.Hostname()
				if _, err := ipc.ServeSetup(ctx, cfg.Socket, ipc.Options{Group: cfg.SocketGroup, Users: cfg.SocketUsers}, node.Status{NodeName: host, Enrollment: "unknown"}, upd,
					func(s ipc.Settings) error { return ipc.SaveSettings(settingsPath, s) }); err != nil {
					return err
				}
				continue
			}
			local.ControlAddr, local.ControlServerName = s.ControlAddr, s.ControlServerName
			if s.Name != "" {
				local.Name = s.Name
			}
		}
		err := runNode(ctx, cfg, local, logs, fromFile, settingsPath, upd)
		if errors.Is(err, ipc.ErrReset) {
			logs.System.Warn("control plane forgotten; back to setup mode")
			continue
		}
		return err
	}
	return nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func runNode(ctx context.Context, cfg config, local ipc.Settings, logs *logging.Streams, fromFile bool, settingsPath string, upd *update.Service) error {
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
	n, err := node.New(node.Config{
		Name:              local.Name,
		StateDir:          cfg.StateDir,
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
		LoginPassthrough:  cfg.LoginPassthrough,
		DNS:               cfg.DNS,
		NoPaths:           cfg.Paths.Disabled,
		PathsListen:       cfg.Paths.Listen,
		PathIdle:          cfg.Paths.Idle,
		AutoUp:            cfg.AutoUp,
		Profile:           cfg.Profile,
		ProfilesDir:       cfg.ProfilesDir,
		TUNName:           cfg.TUNName,
		HubAddrs:          cfg.HubAddrs,
		AllowOverlap:      cfg.AllowOverlap,
		MTU:               cfg.MTU,
		Log:               logs.System,
		FlowLog:           logs.Flow,
	})
	if err != nil {
		return err
	}
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
	opt := ipc.Options{Group: cfg.SocketGroup, Users: cfg.SocketUsers, Update: upd}
	logs.System.Info("node ready", "socket", cfg.Socket, "control", local.ControlAddr, "auto_up", cfg.AutoUp)
	if !fromFile {
		// Forget the control plane: its address, its pinned key and the admin
		// key list learned from it. The device key stays, and to the next
		// control plane this is simply a node that enrolls - unless a new
		// identity is asked for (from a software key to the Secure Enclave,
		// key_kind auto): then the key files go as well.
		opt.Reset = func(newIdentity bool) error { return ipc.Forget(cfg.StateDir, settingsPath, newIdentity) }
	}
	return ipc.Serve(ctx, cfg.Socket, n, opt)
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
