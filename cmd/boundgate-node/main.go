// boundgate-node is the privileged daemon of every BoundGate participant:
// endpoint, subnet router, hub or exit node, decided by the roles an admin
// granted. Control it with boundgatectl over the local socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
	Control  struct {
		Addr       string `yaml:"addr"`
		ServerName string `yaml:"server_name"`
		// Pin is the hex SPKI hash of the control plane's node-channel key;
		// empty = trust on first use (stored in state_dir/control.pin).
		Pin string `yaml:"pin"`
	} `yaml:"control"`
	Roles       []string          `yaml:"roles"`
	Prefixes    []registry.Prefix `yaml:"prefixes"`
	PublicAddr  string            `yaml:"public_addr"`
	Listen      string            `yaml:"listen"`
	AutoUp      bool              `yaml:"auto_up"`
	Profile     string            `yaml:"profile"`
	ProfilesDir string            `yaml:"profiles_dir"`
	Socket      string            `yaml:"socket"`
	TUNName     string            `yaml:"tun_name"`
	HubAddrs    map[string]string `yaml:"hub_addrs"` // dial override per hub name or public_addr
	MTU         int               `yaml:"mtu"`
	LogDir      string            `yaml:"log_dir"`
	LogStdout   bool              `yaml:"log_stdout"`
}

func main() {
	cfgPath := flag.String("config", "/etc/boundgate/node.yaml", "configuration file")
	flag.Parse()
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

	n, err := node.New(node.Config{
		Name:              cfg.Name,
		StateDir:          cfg.StateDir,
		KeyKind:           cfg.KeyKind,
		ControlAddr:       cfg.Control.Addr,
		ControlServerName: cfg.Control.ServerName,
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
		MTU:               cfg.MTU,
		Log:               logs.System,
		FlowLog:           logs.Flow,
	})
	if err != nil {
		return err
	}
	defer n.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go n.Run(ctx)
	logs.System.Info("node ready", "socket", cfg.Socket, "control", cfg.Control.Addr, "auto_up", cfg.AutoUp)
	return ipc.Serve(ctx, cfg.Socket, n)
}
