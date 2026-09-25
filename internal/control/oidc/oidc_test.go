package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc/oidctest"
)

// drive follows the fake IdP's redirect and returns code and state.
func drive(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rsp, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	loc, err := url.Parse(rsp.Header.Get("Location"))
	if err != nil || rsp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %v", rsp.StatusCode, err)
	}
	return loc.Query().Get("code"), loc.Query().Get("state")
}

func TestIdentityFromClaims(t *testing.T) {
	for _, c := range []struct {
		verified any
		email    string
	}{
		{nil, "u@example.test"}, // absent: the IdP did not say
		{true, "u@example.test"},
		{"true", "u@example.test"},
		{false, ""},
		{"false", ""},
		{"FALSE", ""},
	} {
		claims := map[string]any{"email": "u@example.test", "preferred_username": "martin", "groups": []any{"vpn", "admins", "vpn", " ", 7, "admins"}}
		if c.verified != nil {
			claims["email_verified"] = c.verified
		}
		id := identityFrom("u1", claims, "groups")
		if id.Email != c.email {
			t.Errorf("email_verified %v: email %q", c.verified, id.Email)
		}
		if strings.Join(id.Groups, ",") != "vpn,admins" || id.Username != "martin" || id.Subject != "u1" {
			t.Errorf("identity %+v", id)
		}
	}
}

func TestUnverifiedEmailIsDropped(t *testing.T) {
	no := false
	fake := oidctest.New("", "bg", "secret", oidctest.User{Subject: "u1", Email: "ceo@example.test", EmailVerified: &no, Username: "martin", Groups: []string{"vpn", "vpn"}})
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	fake.Issuer = srv.URL
	p, err := New(context.Background(), Config{Issuer: srv.URL, ClientID: "bg", ClientSecret: "secret", RedirectURL: "https://control.test/api/v1/oidc/callback"})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := NewFlow()
	code, _ := drive(t, p.AuthURL(f))
	id, err := p.Exchange(context.Background(), f, code)
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "" || len(id.Groups) != 1 {
		t.Fatalf("%+v", id)
	}
}

func TestCodeFlow(t *testing.T) {
	var srv *httptest.Server
	fake := oidctest.New("", "bg", "secret", oidctest.User{Subject: "u1", Email: "u1@example.test", Username: "martin", Groups: []string{"vpn", "admins"}})
	srv = httptest.NewServer(fake.Handler())
	defer srv.Close()
	fake.Issuer = srv.URL

	p, err := New(context.Background(), Config{Issuer: srv.URL, ClientID: "bg", ClientSecret: "secret", RedirectURL: "https://control.test/api/v1/oidc/callback"})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := NewFlow()
	u := p.AuthURL(f)
	if !strings.Contains(u, "code_challenge_method=S256") || !strings.Contains(u, "nonce="+f.Nonce) || !strings.Contains(u, "scope=openid+profile+email+groups") {
		t.Fatal(u)
	}
	code, state := drive(t, u)
	if state != f.State {
		t.Fatal("state")
	}
	id, err := p.Exchange(context.Background(), f, code)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "u1" || id.Email != "u1@example.test" || id.Username != "martin" || len(id.Groups) != 2 {
		t.Fatalf("%+v", id)
	}
	// a code cannot be redeemed twice
	if _, err := p.Exchange(context.Background(), f, code); err == nil {
		t.Fatal("code replay accepted")
	}
	// wrong PKCE verifier / nonce: refused
	code, _ = drive(t, u)
	bad := f
	bad.Verifier = "x"
	if _, err := p.Exchange(context.Background(), bad, code); err == nil {
		t.Fatal("wrong verifier accepted")
	}
	code, _ = drive(t, u)
	bad = f
	bad.Nonce = "other"
	if _, err := p.Exchange(context.Background(), bad, code); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("wrong nonce: %v", err)
	}
	// wrong client secret at the control plane: refused
	p2, _ := New(context.Background(), Config{Issuer: srv.URL, ClientID: "bg", ClientSecret: "nope", RedirectURL: "https://control.test/api/v1/oidc/callback"})
	code, _ = drive(t, p2.AuthURL(f))
	if _, err := p2.Exchange(context.Background(), f, code); err == nil {
		t.Fatal("wrong secret accepted")
	}
}
