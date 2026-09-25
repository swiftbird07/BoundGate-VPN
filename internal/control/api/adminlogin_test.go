package api_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc/oidctest"
)

// next= after an admin login must stay on this server. Browsers read a
// backslash as a slash and drop tabs and newlines, so "/\evil.example" and
// "/\t/evil.example" lead to //evil.example.
func TestAdminLoginNextStaysLocal(t *testing.T) {
	for _, bad := range []string{`/\evil.example`, "/\t/evil.example", `/\\`, `/\`, "//", "//evil.example", "https://x", "http:/x", "x", "",
		"/\n/evil.example", "/ /evil.example", "/" + string(rune(0xa0)) + "/evil.example", "/\x7f/x", "javascript:alert(1)", "/%09/evil.example\t",
		"/%5C", "/%5Cevil.example", "/%09/x", "/%2F/evil.example", "/%zz"} {
		if got := api.LocalPathForTest(bad); got != "/" {
			t.Errorf("next %q became %q", bad, got)
		}
	}
	for _, ok := range []string{"/", "/nodes", "/nodes?id=abc", "/logs?tab=flows&node=x#top", "/nodes?q=a%20b"} {
		if got := api.LocalPathForTest(ok); got != ok {
			t.Errorf("next %q became %q", ok, got)
		}
	}

	// end to end: the query decodes %5C and %09 before the check
	e := newEnv(t)
	e.withAdminIdP(t, oidctest.User{Subject: "a1", Email: "a1@example.test", Username: "alice", Groups: []string{"admins"}})
	for raw, want := range map[string]string{"/%5Cevil.example": "/", "/%09/evil.example": "/", "%2F%5C%5C": "/", "/nodes": "/nodes", "https%3A%2F%2Fx": "/"} {
		if code, loc := e.adminLogin(browserClient(), raw); code != http.StatusFound || loc != want {
			t.Errorf("next=%s: %d %q, want %q", raw, code, loc, want)
		}
	}
}

// The admin login entry point stores a flow per request without any
// authentication: it is rate limited per client and bounded overall.
func TestAdminLoginStartIsBounded(t *testing.T) {
	e := newEnv(t)
	e.withAdminIdP(t, oidctest.User{Subject: "a1", Groups: []string{"admins"}})
	c := browserClient()
	get := func() int {
		rsp, err := c.Get(e.admin.URL + "/api/v1/admin/auth/login?next=" + url.QueryEscape("/"))
		if err != nil {
			t.Fatal(err)
		}
		rsp.Body.Close()
		return rsp.StatusCode
	}
	for i := 0; i < 10; i++ {
		if code := get(); code != http.StatusFound {
			t.Fatalf("login %d: %d", i, code)
		}
	}
	if code := get(); code != http.StatusTooManyRequests {
		t.Fatalf("11th login a minute from one address: %d", code)
	}

	e.handlers.ResetRateLimitsForTest()
	ctx := context.Background()
	for i := 0; i < 1000; i++ {
		if _, err := e.store.CreateAdminLoginFlow(ctx, "s"+strconv.Itoa(i), "n", "v", "/"); err != nil {
			t.Fatal(err)
		}
	}
	if code := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("login with 1000 pending: %d", code)
	}
}
