// Package oidctest is a minimal OpenID Connect provider for tests and the
// development lab: discovery, JWKS, an authorization endpoint that logs a
// configured user in without asking, and a token endpoint that checks the
// client secret and PKCE and issues an RS256 ID token. Never use it for
// anything real.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// User is who the fake logs in.
type User struct {
	Subject  string
	Email    string
	Username string
	Groups   []string
}

// Provider is the fake IdP. Mount it (Handler) under Issuer.
type Provider struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	User         User
	// TokenLifetime of issued ID tokens (default 5 min).
	TokenLifetime time.Duration

	key   *rsa.PrivateKey
	kid   string
	mu    sync.Mutex
	codes map[string]pending
}

type pending struct {
	nonce, challenge, redirect string
	user                        User
	expires                     time.Time
}

// New creates a provider with a fresh signing key.
func New(issuer, clientID, clientSecret string, user User) *Provider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Provider{Issuer: strings.TrimRight(issuer, "/"), ClientID: clientID, ClientSecret: clientSecret, User: user,
		TokenLifetime: 5 * time.Minute, key: key, kid: "fake-1", codes: map[string]pending{}}
}

// Handler serves the provider.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	return mux
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"jwks_uri":                              p.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig"}}})
}

// authorize logs the configured user in immediately. ?user=<subject> and
// ?groups=a,b override the user for tests; ?deny=1 simulates a refusal.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" {
		http.Error(w, "unknown client or response_type", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Scheme == "" {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := redirect.Query()
	rq.Set("state", q.Get("state"))
	if q.Get("deny") != "" {
		rq.Set("error", "access_denied")
		rq.Set("error_description", "the user refused")
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
		return
	}
	user := p.User
	if u := q.Get("user"); u != "" {
		user = User{Subject: u, Email: u + "@example.test", Username: u}
	}
	if g := q.Get("groups"); g != "" {
		user.Groups = strings.Split(g, ",")
	}
	code := randomString()
	p.mu.Lock()
	p.codes[code] = pending{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), user: user, expires: time.Now().Add(5 * time.Minute)}
	p.mu.Unlock()
	rq.Set("code", code)
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(p.ClientSecret)) != 1 {
		tokenError(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	pd, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	if !ok || time.Now().After(pd.expires) {
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if pd.redirect != r.PostForm.Get("redirect_uri") {
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if pd.challenge != "" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != pd.challenge {
			tokenError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.Issuer, "sub": pd.user.Subject, "aud": p.ClientID,
		"iat": now.Unix(), "exp": now.Add(p.TokenLifetime).Unix(), "nonce": pd.nonce,
		"email": pd.user.Email, "preferred_username": pd.user.Username, "groups": pd.user.Groups,
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", p.kid))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"access_token": randomString(), "token_type": "Bearer", "expires_in": int(p.TokenLifetime.Seconds()), "id_token": raw})
}

func tokenError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
