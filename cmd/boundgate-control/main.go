// boundgate-control is the control plane: node approval, per-node registry
// snapshots, admin API (and SPA from M4), OIDC (from M2). One port, 443.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
)

type config struct {
	Listen             string   `yaml:"listen"`
	ServerName         string   `yaml:"server_name"`
	ExtraNames         []string `yaml:"extra_names"`
	NodeServerName     string   `yaml:"node_server_name"`
	TLSCert            string   `yaml:"tls_cert"`
	TLSKey             string   `yaml:"tls_key"`
	NodeCert           string   `yaml:"node_cert"`
	NodeKey            string   `yaml:"node_key"`
	DBPath             string   `yaml:"db_path"`
	BootstrapTokenFile string   `yaml:"bootstrap_token_file"`
	PendingTTL         string   `yaml:"pending_ttl"`
	LogRetention       string   `yaml:"log_retention"`
	LogDir             string   `yaml:"log_dir"`
	LogStdout          bool     `yaml:"log_stdout"`
	OIDC               struct {
		Issuer           string   `yaml:"issuer"`
		ClientID         string   `yaml:"client_id"`
		ClientSecret     string   `yaml:"client_secret"`
		ClientSecretFile string   `yaml:"client_secret_file"`
		RedirectURL      string   `yaml:"redirect_url"`
		Scopes           []string `yaml:"scopes"`
		GroupsClaim      string   `yaml:"groups_claim"`
		SessionLifetime  string   `yaml:"session_lifetime"`
	} `yaml:"oidc"`
	Admin struct {
		RPID            string   `yaml:"rp_id"`   // WebAuthn relying party id; default server_name
		Origins         []string `yaml:"origins"` // browser origins; default https://<rp_id>
		Group           string   `yaml:"group"`   // OIDC group of administrators; default admins
		SessionLifetime string   `yaml:"session_lifetime"`
	} `yaml:"admin"`
	BehindMux *struct {
		ID              int      `yaml:"id"`                // 1..255, first byte of this server's QUIC connection IDs
		Trusted         []string `yaml:"trusted"`           // the front's addresses, e.g. [127.0.0.1]
		NoProxyProtocol bool     `yaml:"no_proxy_protocol"` // the TCP front sends no PROXY v2 header
	} `yaml:"behind_mux"`
	ACME struct {
		Enabled      bool   `yaml:"enabled"`       // admin certificate from Let's Encrypt (TLS-ALPN-01 on :443)
		Email        string `yaml:"email"`         // optional contact for the CA
		CacheDir     string `yaml:"cache_dir"`     // default: <dir of db_path>/acme
		DirectoryURL string `yaml:"directory_url"` // default: Let's Encrypt production
	} `yaml:"acme"`
}

func main() {
	cfgPath := flag.String("config", "/etc/boundgate/control.yaml", "configuration file")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-control:", err)
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
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&cfg.Listen, ":443")
	def(&cfg.TLSCert, "/var/lib/boundgate/control.crt")
	def(&cfg.TLSKey, "/var/lib/boundgate/control.key")
	def(&cfg.NodeCert, "/var/lib/boundgate/nodes.crt")
	def(&cfg.NodeKey, "/var/lib/boundgate/nodes.key")
	def(&cfg.DBPath, "/var/lib/boundgate/control.db")
	logs, err := logging.Open(logging.Options{Dir: cfg.LogDir, Stdout: cfg.LogStdout || cfg.LogDir == "", Component: "control"})
	if err != nil {
		return err
	}
	defer logs.Close()
	slog.SetDefault(logs.System)

	var pendingTTL, retention time.Duration
	if cfg.PendingTTL != "" {
		if pendingTTL, err = time.ParseDuration(cfg.PendingTTL); err != nil {
			return fmt.Errorf("config: pending_ttl: %w", err)
		}
	}
	if cfg.LogRetention != "" {
		if retention, err = time.ParseDuration(cfg.LogRetention); err != nil {
			return fmt.Errorf("config: log_retention: %w", err)
		}
	}
	oc := oidc.Config{Issuer: cfg.OIDC.Issuer, ClientID: cfg.OIDC.ClientID, ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURL: cfg.OIDC.RedirectURL, Scopes: cfg.OIDC.Scopes, GroupsClaim: cfg.OIDC.GroupsClaim}
	if cfg.OIDC.ClientSecretFile != "" {
		b, err := os.ReadFile(cfg.OIDC.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("config: oidc.client_secret_file: %w", err)
		}
		oc.ClientSecret = strings.TrimSpace(string(b))
	}
	if cfg.OIDC.SessionLifetime != "" {
		if oc.SessionLifetime, err = time.ParseDuration(cfg.OIDC.SessionLifetime); err != nil {
			return fmt.Errorf("config: oidc.session_lifetime: %w", err)
		}
	}
	adminCfg := api.AdminConfig{RPID: cfg.Admin.RPID, Origins: cfg.Admin.Origins, Group: cfg.Admin.Group}
	if cfg.Admin.SessionLifetime != "" {
		if adminCfg.SessionLifetime, err = time.ParseDuration(cfg.Admin.SessionLifetime); err != nil {
			return fmt.Errorf("config: admin.session_lifetime: %w", err)
		}
	}
	var behindMux *control.BehindMux
	if m := cfg.BehindMux; m != nil {
		if m.ID < 1 || m.ID > 255 {
			return errors.New("config: behind_mux.id must be 1..255")
		}
		trusted, err := mux.ParseTrusted(m.Trusted)
		if err != nil || len(trusted) == 0 {
			return fmt.Errorf("config: behind_mux.trusted: %v", err)
		}
		behindMux = &control.BehindMux{ID: byte(m.ID), Trusted: trusted, NoProxyProtocol: m.NoProxyProtocol}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return control.Run(ctx, control.Config{
		Listen:             cfg.Listen,
		ServerName:         cfg.ServerName,
		ExtraNames:         cfg.ExtraNames,
		NodeServerName:     cfg.NodeServerName,
		TLSCert:            cfg.TLSCert,
		TLSKey:             cfg.TLSKey,
		NodeCert:           cfg.NodeCert,
		NodeKey:            cfg.NodeKey,
		DBPath:             cfg.DBPath,
		BootstrapTokenFile: cfg.BootstrapTokenFile,
		PendingTTL:         pendingTTL,
		LogRetention:       retention,
		Logs:               logs,
		OIDC:               oc,
		Admin:              adminCfg,
		BehindMux:          behindMux,
		ACME:               control.ACMEConfig{Enabled: cfg.ACME.Enabled, Email: cfg.ACME.Email, CacheDir: cfg.ACME.CacheDir, DirectoryURL: cfg.ACME.DirectoryURL},
	})
}
