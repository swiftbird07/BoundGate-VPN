package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc/oidctest"
)

func sessionCookie(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	u, _ := url.Parse(base)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "bg_admin" {
			return ck.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

// The session id a browser has at oidc_only is not the one that carries
// full rights: the passkey step issues a new one and revokes the old
// (session fixation). An API token minted with the bootstrap token dies
// with it at the first passkey.
func TestPasskeyRaisesANewSession(t *testing.T) {
	e := newEnv(t)
	e.withAdminIdP(t, oidctest.User{Subject: "alice", Email: "alice@example.test", Username: "alice", Groups: []string{"admins"}})

	var boot api.TokenView
	e.adminCall("POST", "/api/v1/admin/tokens", `{"name":"lab"}`, http.StatusCreated, &boot)
	bearer := func(token string) int {
		req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/admin/nodes", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		rsp.Body.Close()
		return rsp.StatusCode
	}
	if code := bearer(boot.Token); code != http.StatusOK || !boot.Bootstrap {
		t.Fatalf("token minted with the bootstrap token: %d %+v", code, boot)
	}

	c := browserClient()
	e.adminLogin(c, "/")
	before := sessionCookie(t, c, e.admin.URL)
	a := newSoftAuth(e.admin.URL)
	if code, b := e.registerPasskey(c, a, e.boot); code != http.StatusCreated {
		t.Fatalf("first passkey: %d %s", code, b)
	}
	after := sessionCookie(t, c, e.admin.URL)
	if after == before || e.status(c).Level != "full" {
		t.Fatalf("registration kept the session id (%v) or did not raise it", after == before)
	}
	old := &http.Client{}
	req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/admin/me", nil)
	req.AddCookie(&http.Cookie{Name: "bg_admin", Value: before})
	if rsp, err := old.Do(req); err != nil || rsp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the oidc_only id still works: %v %v", rsp.StatusCode, err)
	}
	if code := bearer(boot.Token); code != http.StatusUnauthorized {
		t.Fatalf("token of the bootstrap token after the first passkey: %d", code)
	}
	var toks []api.TokenView
	_, b := e.call(c, "GET", "/api/v1/admin/tokens", "")
	_ = json.Unmarshal(b, &toks)
	if len(toks) != 1 || toks[0].RevokedAt == nil || toks[0].RevokedBy != "first passkey" {
		t.Fatalf("tokens after the first passkey: %s", b)
	}

	// the same for a passkey login in a new browser
	c2 := browserClient()
	e.adminLogin(c2, "/")
	before = sessionCookie(t, c2, e.admin.URL)
	if code, b := e.loginPasskey(c2, a); code != http.StatusOK {
		t.Fatalf("passkey login: %d %s", code, b)
	}
	if sessionCookie(t, c2, e.admin.URL) == before || e.status(c2).Level != "full" {
		t.Fatal("passkey login kept the session id")
	}
	req, _ = http.NewRequest("GET", e.admin.URL+"/api/v1/admin/me", nil)
	req.AddCookie(&http.Cookie{Name: "bg_admin", Value: before})
	if rsp, err := old.Do(req); err != nil || rsp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the oidc_only id still works after the login: %v %v", rsp.StatusCode, err)
	}
}

// A signature counter that goes backwards means two copies of the key;
// go-webauthn only flags it, the control plane refuses the login.
func TestClonedPasskeyIsRefused(t *testing.T) {
	e := newEnv(t)
	e.withAdminIdP(t, oidctest.User{Subject: "alice", Groups: []string{"admins"}})
	c := browserClient()
	e.adminLogin(c, "/")
	a := newSoftAuth(e.admin.URL)
	if code, b := e.registerPasskey(c, a, e.boot); code != http.StatusCreated {
		t.Fatalf("first passkey: %d %s", code, b)
	}
	for i := 0; i < 3; i++ {
		c := browserClient()
		e.adminLogin(c, "/")
		if code, b := e.loginPasskey(c, a); code != http.StatusOK {
			t.Fatalf("login %d: %d %s", i, code, b)
		}
	}
	clone := *a
	clone.count = 1 // a copy of the key that was used less often
	c2 := browserClient()
	e.adminLogin(c2, "/")
	if code, b := e.loginPasskey(c2, &clone); code != http.StatusForbidden || !strings.Contains(string(b), "counter went backwards") {
		t.Fatalf("cloned passkey: %d %s", code, b)
	}
	if st := e.status(c2); st.Level != "oidc_only" {
		t.Fatalf("level after a refused clone: %+v", st)
	}
	// the original, still ahead, keeps working
	c3 := browserClient()
	e.adminLogin(c3, "/")
	if code, b := e.loginPasskey(c3, a); code != http.StatusOK {
		t.Fatalf("original after the clone: %d %s", code, b)
	}
	if _, b := e.call(c3, "GET", "/api/v1/admin/logs?stream=admin-auth", ""); !strings.Contains(string(b), "cloned authenticator") {
		t.Fatalf("clone not audited: %s", b)
	}
}
