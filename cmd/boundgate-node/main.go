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
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gopkg.in/yaml.v3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

type config struct {
	Name     string `yaml:"name"`
	StateDir string `yaml:"state_dir"`
	KeyKind  string `yaml:"key_kind"`
	// TPMDevice: for key_kind tpm2; default /dev/tpmrm0, or unix:PATH / tcp:HOST:PORT (swtpm)
	TPMDevice string `yaml:"tpm_device"`
	Control   struct {
		Addr       string `yaml:"addr"`
		ServerName string `yaml:"server_name"`
		// Pin is the hex SPKI hash of the control plane's node-channel key;
		// empty = trust on first use (stored in state_dir/control.pin).
		Pin string `yaml:"pin"`
	} `yaml:"control"`
	Roles        []string          `yaml:"roles"`
	Prefixes     []registry.Prefix `yaml:"prefixes"`
	PublicAddr   string            `yaml:"public_addr"`
	Listen       string            `yaml:"listen"`
	AutoUp       bool              `yaml:"auto_up"`
	Profile      string            `yaml:"profile"`
	ProfilesDir  string            `yaml:"profiles_dir"`
	Socket       string            `yaml:"socket"`
	SocketGroup  string            `yaml:"socket_group"` // group that may use the socket next to root (macOS app: admin)
	TUNName      string            `yaml:"tun_name"`
	HubAddrs     map[string]string `yaml:"hub_addrs"`     // dial override per hub name or public_addr
	AllowOverlap bool              `yaml:"allow_overlap"` // route networks this machine already lives in (overlap guard off)
	MTU          int               `yaml:"mtu"`
	LogDir       string            `yaml:"log_dir"`
	LogStdout    bool              `yaml:"log_stdout"`
}

func main() {
	cfgPath := flag.String("config", "", "configuration file (default: node.yaml next to the executable, else /etc/boundgate/node.yaml)")
	flag.Parse()
	if *cfgPath == "" {
		*cfgPath = "/etc/boundgate/node.yaml"
		// a package ships its configuration next to the daemon; a macOS app
		// bundle has it in Contents/Resources (the daemon is in Contents/MacOS)
		if exe, err := os.Executable(); err == nil {
			for _, p := range []string{filepath.Join(filepath.Dir(exe), "node.yaml"), filepath.Join(filepath.Dir(exe), "..", "Resources", "node.yaml")} {
				if fileExists(p) {
					*cfgPath = p
					break
				}
			}
		}
	}
	if err := run(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	var cfg config
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "/var/lib/boundgate"
	}
	if cfg.ProfilesDir == "" {
		cfg.ProfilesDir = "/etc/boundgate/profiles"
	}
	if cfg.Socket == "" {
		cfg.Socket = "/run/boundgate/node.sock"
	}
	logs, err := logging.Open(logging.Options{Dir: cfg.LogDir, Stdout: cfg.LogStdout || cfg.LogDir == "", Component: "node"})
	if err != nil {
		return err
	}
	defer logs.Close()
	slog.SetDefault(logs.System)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// A configuration file that names the control plane is final. Without
	// one, the user decides (boundgatectl configure, or the app): setup mode
	// until then, and `reset` leads back here.
	fromFile := cfg.Control.Addr != ""
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
				if _, err := ipc.ServeSetup(ctx, cfg.Socket, cfg.SocketGroup, node.Status{NodeName: host, Enrollment: "unknown"},
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
		err := runNode(ctx, cfg, local, logs, fromFile, settingsPath)
		if errors.Is(err, ipc.ErrReset) {
			logs.System.Warn("control plane forgotten; back to setup mode")
			continue
		}
		return err
	}
	return nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func runNode(ctx context.Context, cfg config, local ipc.Settings, logs *logging.Streams, fromFile bool, settingsPath string) error {
	n, err := node.New(node.Config{
		Name:              local.Name,
		StateDir:          cfg.StateDir,
		KeyKind:           cfg.KeyKind,
		TPMDevice:         cfg.TPMDevice,
		ControlAddr:       local.ControlAddr,
		ControlServerName: local.ControlServerName,
		ControlPin:        cfg.Control.Pin,
		Roles:             cfg.Roles,
		Prefixes:          cfg.Prefixes,
		PublicAddr:        cfg.PublicAddr,
		Listen:            cfg.Listen,
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
	defer n.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go n.Run(ctx)
	logs.System.Info("node ready", "socket", cfg.Socket, "control", local.ControlAddr, "auto_up", cfg.AutoUp)
	opt := ipc.Options{Group: cfg.SocketGroup}
	if !fromFile {
		// Forget the control plane: its address, its pinned key and the admin
		// keys learned from it. The device key stays; to the next control
		// plane this is simply a node that enrolls.
		opt.Reset = func() error {
			for _, f := range []string{settingsPath, filepath.Join(cfg.StateDir, "control.pin"), filepath.Join(cfg.StateDir, "admin_keys")} {
				if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			return nil
		}
	}
	return ipc.Serve(ctx, cfg.Socket, n, opt)
}
