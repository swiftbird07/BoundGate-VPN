// Package control wires the control plane: database, snapshot source, one
// port (443, TCP and UDP) for admins and nodes, and housekeeping.
//
// The TLS server name decides who is talking:
//
//   - the admin name (WebPKI in production, self-signed in dev) serves the
//     admin API and, from M4, the SPA; no client certificate is requested
//   - the node name serves the node API with the control plane's own
//     long-lived key and requires a device client certificate
package control

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/web"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/snapshot"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/servercert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Config for the control plane.
type Config struct {
	// Listen is the address for both the TCP and the UDP listener, e.g. ":443".
	Listen string
	// ServerName is the admin (browser) name; ExtraNames go into the dev
	// certificate as well (IPs, localhost).
	ServerName string
	ExtraNames []string
	// TLSCert/TLSKey: the admin certificate; created self-signed if absent.
	TLSCert string
	TLSKey  string
	// NodeServerName is the SNI nodes use; default "nodes." + ServerName.
	NodeServerName string
	// NodeCert/NodeKey: the control plane's long-lived node-channel identity;
	// created if absent. Nodes pin this key; rotating it means every node
	// must be re-pinned (delete control.pin) - never do it casually.
	NodeCert string
	NodeKey  string
	DBPath   string
	// BootstrapTokenFile, if set, receives the bootstrap token on first
	// start (0600). Otherwise the token is only printed to the system log.
	BootstrapTokenFile string
	PendingTTL         time.Duration
	LogRetention       time.Duration
	Logs               *logging.Streams
	// OIDC configures user logins; an empty issuer disables them.
	OIDC oidc.Config
	// Admin configures browser logins; RPID defaults to ServerName.
	Admin api.AdminConfig
	// ACME obtains the admin certificate from a public CA (Let's Encrypt)
	// instead of TLSCert/TLSKey. The node channel is not affected: nodes pin
	// its own long-lived key.
	ACME ACMEConfig
	// NoSPA disables the embedded admin UI (tests).
	NoSPA bool
}

// ACMEConfig: certificates for the admin name by TLS-ALPN-01 on the TCP
// listener itself, so nothing but port 443 is needed.
type ACMEConfig struct {
	Enabled bool
	// Email receives the CA's expiry and policy mail (optional).
	Email string
	// CacheDir keeps account key and certificates (0700).
	CacheDir string
	// DirectoryURL overrides the CA (default: Let's Encrypt production;
	// its staging directory is the way to try a setup without rate limits).
	DirectoryURL string
}

// AdminCertFunc supplies the admin certificate per handshake (ACME).
type AdminCertFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// TLSConfigACME is TLSConfig with the admin certificate coming from get.
// On the TCP listener protos must contain acme.ALPNProto so the CA can
// validate the name.
func TLSConfigACME(get AdminCertFunc, nodeCert tls.Certificate, nodeServerName string, protos []string) *tls.Config {
	cfg := TLSConfig(tls.Certificate{}, nodeCert, nodeServerName, protos)
	split := cfg.GetConfigForClient
	adminCfg := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: get, NextProtos: protos}
	cfg.Certificates, cfg.GetCertificate = nil, get
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == nodeServerName {
			return split(hello)
		}
		return adminCfg, nil
	}
	return cfg
}

// TLSConfig builds the SNI-splitting server configuration. protos are the
// ALPN identifiers of the listener it serves (h3 on UDP, h2/http1.1 on TCP).
func TLSConfig(adminCert, nodeCert tls.Certificate, nodeServerName string, protos []string) *tls.Config {
	adminCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{adminCert},
		NextProtos:   protos,
	}
	nodeCfg := transport.ServerTLSConfigAnyDevice(nodeCert)
	nodeCfg.NextProtos = protos
	root := adminCfg.Clone()
	root.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == nodeServerName {
			return nodeCfg, nil
		}
		return adminCfg, nil
	}
	return root
}

// Run starts the control plane and blocks until ctx ends.
func Run(ctx context.Context, cfg Config) error {
	log := cfg.Logs.System
	if cfg.ServerName == "" {
		return errors.New("control: server_name is required")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.NodeServerName == "" {
		cfg.NodeServerName = "nodes." + cfg.ServerName
	}
	if cfg.PendingTTL == 0 {
		cfg.PendingTTL = 24 * time.Hour
	}
	if cfg.LogRetention == 0 {
		cfg.LogRetention = 90 * 24 * time.Hour
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o700); err != nil {
		return err
	}
	store, err := db.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	token, created, err := store.EnsureBootstrapToken(ctx)
	if err != nil {
		return err
	}
	if created {
		if cfg.BootstrapTokenFile != "" {
			if err := os.WriteFile(cfg.BootstrapTokenFile, []byte(token+"\n"), 0o600); err != nil {
				return fmt.Errorf("control: write bootstrap token: %w", err)
			}
			log.Info("bootstrap token created", "file", cfg.BootstrapTokenFile)
		} else {
			log.Info("bootstrap token created; it is shown only once", "token", token)
		}
	}

	var adminCert tls.Certificate
	adminCreated := false
	if !cfg.ACME.Enabled {
		if adminCert, adminCreated, err = servercert.LoadOrCreate(cfg.TLSCert, cfg.TLSKey, append([]string{cfg.ServerName}, cfg.ExtraNames...)); err != nil {
			return err
		}
	}
	if adminCreated {
		log.Info("created self-signed admin certificate", "cert", cfg.TLSCert, "names", append([]string{cfg.ServerName}, cfg.ExtraNames...))
	}
	nodeCert, nodeCreated, err := servercert.LoadOrCreate(cfg.NodeCert, cfg.NodeKey, []string{cfg.NodeServerName})
	if err != nil {
		return err
	}
	if nodeCreated {
		log.Info("created node-channel identity", "cert", cfg.NodeCert, "server_name", cfg.NodeServerName)
	}

	nodeSPKI, err := devicekey.HashPublicKey(nodeCert.Leaf.PublicKey)
	if err != nil {
		return err
	}
	log.Info("node-channel key", "spki", nodeSPKI, "fingerprint", nodeSPKI.Fingerprint())
	src := snapshot.New(store)
	idp := oidc.NewLazy(cfg.OIDC)
	if idp == nil {
		log.Warn("no identity provider configured; user logins are disabled (interactive nodes cannot use hubs)")
	} else {
		log.Info("identity provider", "issuer", cfg.OIDC.Issuer, "client_id", cfg.OIDC.ClientID, "redirect_url", cfg.OIDC.RedirectURL)
	}
	if cfg.Admin.RPID == "" {
		cfg.Admin.RPID = cfg.ServerName
	}
	var spa http.Handler
	if !cfg.NoSPA {
		spa = web.Handler()
	}
	h, err := api.NewWithError(api.Deps{DB: store, Snap: src, Logs: cfg.Logs, PendingTTL: cfg.PendingTTL, ControlSPKI: nodeSPKI, OIDC: idp, Admin: cfg.Admin, SPA: spa})
	if err != nil {
		return err
	}
	log.Info("admin logins", "rp_id", cfg.Admin.RPID, "origins", cfg.Admin.Origins, "group", cfg.Admin.Group)
	root := h.Root(cfg.NodeServerName)

	tcpTLS := TLSConfig(adminCert, nodeCert, cfg.NodeServerName, []string{"h2", "http/1.1"})
	udpTLS := TLSConfig(adminCert, nodeCert, cfg.NodeServerName, []string{http3.NextProtoH3})
	if cfg.ACME.Enabled {
		if cfg.ACME.CacheDir == "" {
			cfg.ACME.CacheDir = filepath.Join(filepath.Dir(cfg.DBPath), "acme")
		}
		if err := os.MkdirAll(cfg.ACME.CacheDir, 0o700); err != nil {
			return err
		}
		names := append([]string{cfg.ServerName}, cfg.ExtraNames...)
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(cfg.ACME.CacheDir), HostPolicy: autocert.HostWhitelist(names...), Email: cfg.ACME.Email}
		if cfg.ACME.DirectoryURL != "" {
			m.Client = &acme.Client{DirectoryURL: cfg.ACME.DirectoryURL}
		}
		tcpTLS = TLSConfigACME(m.GetCertificate, nodeCert, cfg.NodeServerName, []string{"h2", "http/1.1", acme.ALPNProto})
		udpTLS = TLSConfigACME(m.GetCertificate, nodeCert, cfg.NodeServerName, []string{http3.NextProtoH3})
		log.Info("admin certificate from ACME (TLS-ALPN-01 on the TCP listener)", "names", names, "cache", cfg.ACME.CacheDir, "directory", cfg.ACME.DirectoryURL)
	}
	tcpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           root,
		TLSConfig:         tcpTLS,
		ReadHeaderTimeout: 10 * time.Second,
	}
	udpSrv := &http3.Server{
		Addr:      cfg.Listen,
		Handler:   root,
		TLSConfig: udpTLS,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  90 * time.Second, // long-polls run 30 s
			KeepAlivePeriod: 20 * time.Second,
			Allow0RTT:       false,
		},
		Logger: log,
	}

	errc := make(chan error, 2)
	go func() {
		log.Info("listening", "tcp", cfg.Listen, "admin_name", cfg.ServerName, "node_name", cfg.NodeServerName)
		errc <- tcpSrv.ListenAndServeTLS("", "")
	}()
	go func() {
		log.Info("listening", "udp", cfg.Listen, "proto", "h3")
		errc <- udpSrv.ListenAndServe()
	}()
	go housekeeping(ctx, store, cfg, log)
	go expireSessions(ctx, store, src, cfg.Logs)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tcpSrv.Shutdown(shutdownCtx)
		_ = udpSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// expireSessions ends user sessions past their lifetime and lets nodes
// know through a snapshot bump. Hubs also enforce expiry locally.
func expireSessions(ctx context.Context, store *db.DB, src *snapshot.Source, logs *logging.Streams) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n, version, err := store.ExpireSessions(ctx)
		if err != nil {
			logs.System.Error("expire sessions", "err", err)
			continue
		}
		if n > 0 {
			src.Notify(version)
			logs.UserAuth.Info("sessions expired", "actor", "system", "count", n, "snapshot_version", version)
		}
	}
}

func housekeeping(ctx context.Context, store *db.DB, cfg Config, log interface {
	Info(string, ...any)
	Error(string, ...any)
}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if n, err := store.ExpirePending(ctx, cfg.PendingTTL); err != nil {
			log.Error("expire pending nodes", "err", err)
		} else if n > 0 {
			log.Info("expired pending enrollment requests", "count", n)
		}
		if _, err := store.ExpireSignTokens(ctx); err != nil {
			log.Error("expire sign tokens", "err", err)
		}
		if n, err := store.PruneLogs(ctx, cfg.LogRetention); err != nil {
			log.Error("prune logs", "err", err)
		} else if n > 0 {
			log.Info("pruned log events", "count", n)
		}
		// hubs report every tunnel at least every 30 s; a hub that fell
		// silent for 3 min has lost them
		if n, err := store.CloseStaleTunnels(ctx, 3*time.Minute); err != nil {
			log.Error("close stale tunnels", "err", err)
		} else if n > 0 {
			log.Info("closed tunnels of silent hubs", "count", n)
		}
		if _, err := store.PruneTunnels(ctx, cfg.LogRetention); err != nil {
			log.Error("prune tunnels", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
