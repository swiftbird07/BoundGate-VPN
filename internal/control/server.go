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
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/listsource"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/snapshot"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/web"
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
	// BootstrapTokenFile receives the bootstrap token on first start and on
	// rotation (0600); default "bootstrap-token" next to the database. The
	// token never goes into a log.
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
	// BehindMux: the control plane shares its public port with other servers
	// (a hub, a web server) behind a boundgate-mux or a TCP reverse proxy in
	// SNI-passthrough mode. Listen is then the private address.
	BehindMux *BehindMux
	// AdminAllow restricts the admin UI and API (every server name but the
	// node name) to client addresses in these prefixes; empty allows all.
	// Enforced per request (adminGate); users' sign-in callback is open to
	// all. The node channel is never restricted: nodes are anywhere.
	AdminAllow []netip.Prefix
	// CertReloadInterval is how often TLSCert/TLSKey are checked for a
	// renewed pair (default 30s; an external ACME client writes them).
	CertReloadInterval time.Duration
	// NoSPA disables the embedded admin UI (tests).
	NoSPA bool
	// ListSources fences where lists that follow a URL may be fetched from
	// (private ranges only when allowed here; docs/ACL.md, R114).
	ListSources listsource.Options
}

// BehindMux configures the listeners of a control plane behind a front.
type BehindMux struct {
	// ID is the first byte of the QUIC connection IDs issued here.
	ID byte
	// Trusted are the front's addresses: only they may deliver UDP, and TCP
	// connections from them start with a PROXY protocol v2 header.
	Trusted []netip.Prefix
	// NoProxyProtocol: the TCP front sends no PROXY header (client addresses
	// are lost for TCP: logs and rate limits see the front).
	NoProxyProtocol bool
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
		// never into the log: logs are shipped and kept for months
		path := bootstrapTokenPath(cfg.DBPath, cfg.BootstrapTokenFile)
		if err := writeSecretFile(path, token); err != nil {
			return fmt.Errorf("control: write bootstrap token: %w", err)
		}
		log.Info("bootstrap token created; it works until the first admin passkey is registered", "file", path)
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
	if cfg.CertReloadInterval == 0 {
		cfg.CertReloadInterval = 30 * time.Second
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
	h, err := api.NewWithError(api.Deps{DB: store, Snap: src, Logs: cfg.Logs, PendingTTL: cfg.PendingTTL, ControlSPKI: nodeSPKI, OIDC: idp, Admin: cfg.Admin, SPA: spa,
		ListSources: listsource.Options{AllowPrivate: cfg.ListSources.AllowPrivate}})
	if err != nil {
		return err
	}
	log.Info("admin logins", "rp_id", cfg.Admin.RPID, "origins", cfg.Admin.Origins, "group", cfg.Admin.Group)
	root := h.Root(cfg.NodeServerName)

	// The admin certificate comes through a callback in every case: from
	// the files (reloaded when an external ACME client renews them) or from
	// the built-in ACME manager.
	reloader := newCertReloader(cfg.TLSCert, cfg.TLSKey, adminCert, cfg.CertReloadInterval)
	reloader.onLoad = func(c *tls.Certificate, err error) {
		if err != nil {
			log.Error("admin certificate files changed but do not load; keeping the old one", "cert", cfg.TLSCert, "err", err)
			return
		}
		if leaf, e := x509.ParseCertificate(c.Certificate[0]); e == nil {
			log.Info("admin certificate reloaded", "cert", cfg.TLSCert, "not_after", leaf.NotAfter.UTC().Format(time.RFC3339), "names", leaf.DNSNames)
		}
	}
	tcpTLS := TLSConfigACME(reloader.Get, nodeCert, cfg.NodeServerName, []string{"h2", "http/1.1"})
	udpTLS := TLSConfigACME(reloader.Get, nodeCert, cfg.NodeServerName, []string{http3.NextProtoH3})
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
	if len(cfg.AdminAllow) > 0 {
		var denied atomic.Int64
		onDeny := func(addr net.Addr) {
			if n := denied.Add(1); n == 1 || n%100 == 0 {
				log.Warn("admin UI refused: address not in admin_allow", "addr", addr, "count", n)
			}
		}
		root = adminGate(cfg.AdminAllow, cfg.NodeServerName, onDeny, root)
		log.Info("admin UI restricted to", "admin_allow", cfg.AdminAllow, "open to all", "GET "+api.OIDCCallbackPath+", POST "+api.OIDCConfirmPath+" (user sign-in)")
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
			MaxIdleTimeout: 90 * time.Second, // long-polls run 30 s
			// No keep-alives from here: nodes that long-poll keep their
			// connection alive themselves, and a phone that polls
			// (node power save) lets it close instead of being woken.
			Allow0RTT: false,
		},
		Logger: log,
	}

	tcpLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	var udpLn http3.QUICListener
	if m := cfg.BehindMux; m != nil {
		if !m.NoProxyProtocol {
			tcpLn = &mux.ProxyListener{Listener: tcpLn, Trusted: m.Trusted}
		}
		pc, err := mux.ListenBackend(cfg.Listen, m.Trusted)
		if err != nil {
			return err
		}
		defer pc.Close()
		qt := &quic.Transport{Conn: pc, ConnectionIDGenerator: mux.CIDGenerator{ID: m.ID}}
		defer qt.Close()
		if udpLn, err = qt.ListenEarly(http3.ConfigureTLSConfig(udpTLS), udpSrv.QUICConfig); err != nil {
			return err
		}
		log.Info("behind a mux", "id", m.ID, "trusted", m.Trusted, "proxy_protocol", !m.NoProxyProtocol)
	}
	errc := make(chan error, 2)
	go func() {
		log.Info("listening", "tcp", cfg.Listen, "admin_name", cfg.ServerName, "node_name", cfg.NodeServerName)
		errc <- tcpSrv.ServeTLS(tcpLn, "", "")
	}()
	go func() {
		log.Info("listening", "udp", cfg.Listen, "proto", "h3")
		if udpLn != nil {
			errc <- udpSrv.ServeListener(udpLn)
			return
		}
		errc <- udpSrv.ListenAndServe()
	}()
	go housekeeping(ctx, store, cfg, log)
	go expireSessions(ctx, store, src, cfg.Logs)
	// lists that follow a URL (docs/ACL.md)
	go listsource.Run(ctx, store, src, cfg.Logs.System, listsource.Options{AllowPrivate: cfg.ListSources.AllowPrivate})

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

// bootstrapTokenPath is where the bootstrap token is written: the
// configured file, or "bootstrap-token" in the state directory.
func bootstrapTokenPath(dbPath, configured string) string {
	if configured != "" {
		return configured
	}
	return filepath.Join(filepath.Dir(dbPath), "bootstrap-token")
}

// writeSecretFile writes a secret that only the owner can read, also when
// the file exists already with wider permissions.
func writeSecretFile(path, secret string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(secret + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// RotateBootstrapToken replaces the bootstrap token and writes the new one
// like the first (boundgate-control rotate-bootstrap-token, on the
// control-plane host). The token works only while no passkey is active, so
// after the last passkey was lost revokePasskeys revokes every passkey
// first: whoever can run this owns the database anyway. It returns the file
// and how many passkeys it revoked and are still active.
func RotateBootstrapToken(ctx context.Context, dbPath, tokenFile string, revokePasskeys bool) (file string, revoked int64, active int, err error) {
	store, err := db.Open(ctx, dbPath)
	if err != nil {
		return "", 0, 0, err
	}
	defer store.Close()
	if revokePasskeys {
		if revoked, err = store.RevokeAllPasskeys(ctx, "host: rotate-bootstrap-token"); err != nil {
			return "", 0, 0, err
		}
	}
	token, err := store.RotateBootstrapToken(ctx)
	if err != nil {
		return "", revoked, 0, err
	}
	file = bootstrapTokenPath(dbPath, tokenFile)
	if err := writeSecretFile(file, token); err != nil {
		return "", revoked, 0, fmt.Errorf("write bootstrap token: %w", err)
	}
	if active, err = store.CountActivePasskeys(ctx); err != nil {
		return file, revoked, 0, err
	}
	store.InsertLog(ctx, db.LogEvent{Stream: logging.StreamAdminAuth, Actor: "host", Message: "bootstrap token rotated",
		Attrs: map[string]any{"file": file, "passkeys_revoked": revoked, "passkeys_active": active}})
	return file, revoked, active, nil
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
		if _, err := store.ExpireSignerChanges(ctx); err != nil {
			log.Error("expire signer list proposals", "err", err)
		}
		// admin logins start without authentication: their flows must not pile up
		if err := store.ExpireAdminSessions(ctx); err != nil {
			log.Error("expire admin sessions and login flows", "err", err)
		}
		if _, err := store.PruneSessions(ctx, cfg.LogRetention); err != nil {
			log.Error("prune ended user sessions", "err", err)
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
