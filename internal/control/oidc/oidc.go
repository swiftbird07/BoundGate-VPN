// Package oidc runs the OpenID Connect authorization-code flow (with PKCE
// and a nonce) for user logins. Only the control plane talks to the IdP;
// nodes never see tokens. The result of a login is a Session in the
// control plane's database, distributed inside snapshots.
//
// Outside the TCB: a bug here can create a wrong user session, which is a
// policy error bounded by the node's device identity; it cannot mint a
// node.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config for the provider.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is the callback on the control plane's admin name, e.g.
	// https://control.example/api/v1/oidc/callback.
	RedirectURL string
	// Scopes default to openid, profile, email, groups.
	Scopes []string
	// GroupsClaim is the ID-token claim carrying group names (default "groups").
	GroupsClaim string
	// SessionLifetime is how long a login is valid (default 10h). Sessions
	// are not tied to token lifetimes; there are no refresh tokens.
	SessionLifetime time.Duration
}

// Provider is a configured IdP.
type Provider struct {
	cfg      Config
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth    oauth2.Config
}

// New runs discovery against the issuer.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: issuer, client_id and redirect_url are required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{gooidc.ScopeOpenID, "profile", "email", "groups"}
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = 10 * time.Hour
	}
	p, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery for %s: %w", cfg.Issuer, err)
	}
	return &Provider{
		cfg:      cfg,
		provider: p,
		verifier: p.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: p.Endpoint(),
			RedirectURL: cfg.RedirectURL, Scopes: cfg.Scopes,
		},
	}, nil
}

// Issuer returns the configured issuer.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// SessionLifetime returns the configured lifetime.
func (p *Provider) SessionLifetime() time.Duration { return p.cfg.SessionLifetime }

// Flow holds the per-login secrets the control plane keeps until the
// callback arrives.
type Flow struct {
	State, Nonce, Verifier string
}

// NewFlow generates state, nonce and PKCE verifier.
func NewFlow() (Flow, error) {
	var f Flow
	var err error
	if f.State, err = random(24); err != nil {
		return f, err
	}
	if f.Nonce, err = random(24); err != nil {
		return f, err
	}
	if f.Verifier, err = random(48); err != nil {
		return f, err
	}
	return f, nil
}

func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthURL returns where the user's browser must go.
func (p *Provider) AuthURL(f Flow) string {
	sum := sha256.Sum256([]byte(f.Verifier))
	return p.oauth.AuthCodeURL(f.State,
		gooidc.Nonce(f.Nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Identity is what a verified login says about the user.
type Identity struct {
	Subject  string
	Email    string
	Username string
	Groups   []string
}

// Exchange redeems the authorization code and verifies the ID token
// (signature, issuer, audience, expiry, nonce).
func (p *Provider) Exchange(ctx context.Context, f Flow, code string) (Identity, error) {
	tok, err := p.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", f.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: token exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, errors.New("oidc: token response without id_token")
	}
	idt, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: id token: %w", err)
	}
	if idt.Nonce != f.Nonce {
		return Identity{}, errors.New("oidc: id token nonce mismatch")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oidc: claims: %w", err)
	}
	id := Identity{Subject: idt.Subject}
	id.Email, _ = claims["email"].(string)
	id.Username, _ = claims["preferred_username"].(string)
	if id.Username == "" {
		id.Username, _ = claims["name"].(string)
	}
	if gs, ok := claims[p.cfg.GroupsClaim].([]any); ok {
		for _, g := range gs {
			if s, ok := g.(string); ok && strings.TrimSpace(s) != "" {
				id.Groups = append(id.Groups, s)
			}
		}
	}
	if id.Subject == "" {
		return Identity{}, errors.New("oidc: id token without subject")
	}
	return id, nil
}

// Lazy defers discovery until the first login so the control plane starts
// even when the IdP is not reachable yet, and retries on the next use.
type Lazy struct {
	cfg Config
	mu  sync.Mutex
	p   *Provider
}

// NewLazy returns a provider that connects on first use; nil config
// (empty issuer) means logins are disabled.
func NewLazy(cfg Config) *Lazy {
	if cfg.Issuer == "" {
		return nil
	}
	return &Lazy{cfg: cfg}
}

// Get returns the provider, running discovery if needed.
func (l *Lazy) Get(ctx context.Context) (*Provider, error) {
	if l == nil {
		return nil, ErrDisabled
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p != nil {
		return l.p, nil
	}
	p, err := New(ctx, l.cfg)
	if err != nil {
		return nil, err
	}
	l.p = p
	return p, nil
}

// ErrDisabled is returned when no IdP is configured.
var ErrDisabled = errors.New("oidc: user login is not configured on this control plane")
