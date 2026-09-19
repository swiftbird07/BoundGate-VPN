// boundgate-mux lets a control plane, a hub and whatever else wants port 443
// share one public address: it routes TCP and UDP (QUIC) by TLS server name
// without terminating TLS and holds no key. See internal/mux and
// docs/DEPLOY.md.
//
//	boundgate-mux -config /etc/boundgate/mux.yaml
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
)

type config struct {
	Listen        string   `yaml:"listen"`         // default ":443", TCP and UDP
	ListenTCP     string   `yaml:"listen_tcp"`     // TCP elsewhere than UDP: a reverse proxy in front delivers TLS to this private address
	TrustedFronts []string `yaml:"trusted_fronts"` // those proxies: their PROXY header (v1/v2) carries the client address
	Routes []struct {
		Name          string   `yaml:"name"`
		SNI           []string `yaml:"sni"`
		ID            int      `yaml:"id"`             // behind_mux.id of that server (UDP)
		UDP           string   `yaml:"udp"`            // its private QUIC address
		TCP           string   `yaml:"tcp"`            // its private TLS address
		ProxyProtocol *bool    `yaml:"proxy_protocol"` // PROXY v2 on TCP; default true
	} `yaml:"routes"`
	DefaultTCP           string `yaml:"default_tcp"`                // every other server name, e.g. your web server's TLS port
	DefaultProxyProtocol bool   `yaml:"default_tcp_proxy_protocol"` // send PROXY v2 to default_tcp too (nginx: proxy_protocol on; Traefik: proxyProtocol.trustedIPs; Caddy: proxy_protocol)
	NoTCP                bool   `yaml:"no_tcp"`                     // UDP only: a reverse proxy owns TCP/443 and passes the BoundGate names through
	LogLevel             string `yaml:"log_level"`                  // info (default) | debug
}

func main() {
	cfgPath := flag.String("config", "/etc/boundgate/mux.yaml", "configuration file")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-mux:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).With("component", "mux")
	fronts, err := mux.ParseTrusted(cfg.TrustedFronts)
	if err != nil {
		return fmt.Errorf("config: trusted_fronts: %w", err)
	}
	mc := mux.Config{Listen: cfg.Listen, ListenTCP: cfg.ListenTCP, TrustedFronts: fronts, DefaultTCP: cfg.DefaultTCP, DefaultProxyProtocol: cfg.DefaultProxyProtocol, NoTCP: cfg.NoTCP, Log: log}
	for _, r := range cfg.Routes {
		if r.UDP != "" && (r.ID < 1 || r.ID > 255) {
			return fmt.Errorf("config: route %q: id must be 1..255 and match behind_mux.id of that server", r.Name)
		}
		mc.Routes = append(mc.Routes, mux.Route{Name: r.Name, SNI: r.SNI, ID: byte(r.ID), UDP: r.UDP, TCP: r.TCP, ProxyProtocol: r.ProxyProtocol == nil || *r.ProxyProtocol})
	}
	if len(mc.Routes) == 0 {
		return errors.New("config: no routes")
	}
	f, err := mux.New(mc)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return f.Run(ctx)
}
