package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc/oidctest"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/snapshot"
)

// withAdminIdP attaches a fake IdP and enables browser logins with passkeys
// for rp id "localhost" and the test server's origin.
func (e *env) withAdminIdP(t *testing.T, user oidctest.User) *oidctest.Provider {
	t.Helper()
	fake := oidctest.New("", "bg", "secret", user)
	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)
	fake.Issuer = srv.URL
	h, err := api.NewWithError(api.Deps{DB: e.store, Snap: snapshot.New(e.store), Logs: e.logs,
		OIDC:  oidc.NewLazy(oidc.Config{Issuer: srv.URL, ClientID: "bg", ClientSecret: "secret", RedirectURL: e.admin.URL + "/api/v1/oidc/callback"}),
		Admin: api.AdminConfig{RPID: "localhost", Origins: []string{e.admin.URL}, Group: "admins", SessionLifetime: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	e.handlers = h
	e.admin.Config.Handler = h.AdminMux()
	e.node.Config.Handler = h.NodeMux()
	return fake
}

// browserClient is a cookie-keeping client that does not follow redirects.
func browserClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// call sends a JSON request with the CSRF header the SPA sends.
func (e *env) call(c *http.Client, method, path, body string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.admin.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "BoundGate")
	rsp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	return rsp.StatusCode, b
}

// adminLogin drives the OIDC login of a browser: login → IdP → callback.
func (e *env) adminLogin(c *http.Client, next string) (int, string) {
	e.t.Helper()
	rsp, err := c.Get(e.admin.URL + "/api/v1/admin/auth/login?next=" + next)
	if err != nil {
		e.t.Fatal(err)
	}
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusFound {
		e.t.Fatalf("login start: %d", rsp.StatusCode)
	}
	rsp, err = c.Get(rsp.Header.Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	rsp.Body.Close()
	loc := rsp.Header.Get("Location")
	if rsp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, e.admin.URL+"/api/v1/oidc/callback?") {
		e.t.Fatalf("authorize: %d %s", rsp.StatusCode, loc)
	}
	rsp, err = c.Get(loc)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	if rsp.StatusCode == http.StatusFound {
		return rsp.StatusCode, rsp.Header.Get("Location")
	}
	return rsp.StatusCode, string(b)
}

func (e *env) status(c *http.Client) api.AuthStatus {
	e.t.Helper()
	_, b := e.call(c, "GET", "/api/v1/admin/auth/status", "")
	var st api.AuthStatus
	if err := json.Unmarshal(b, &st); err != nil {
		e.t.Fatal(err)
	}
	return st
}

// softAuth is a software passkey: an ES256 key with a credential id, no
// attestation, user verification always set.
type softAuth struct {
	key    *ecdsa.PrivateKey
	id     []byte
	count  uint32
	origin string
}

func newSoftAuth(origin string) *softAuth {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuth{key: key, id: id, origin: origin}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func challengeOf(t *testing.T, body []byte) string {
	t.Helper()
	var v struct {
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.Options.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in %s", body)
	}
	return v.Options.PublicKey.Challenge
}

func (a *softAuth) authData(flags byte, attested bool) []byte {
	rp := sha256.Sum256([]byte("localhost"))
	a.count++
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if attested {
		out = append(out, make([]byte, 16)...) // aaguid
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
		out = append(out, a.id...)
		x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
		y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
		cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		if err != nil {
			panic(err)
		}
		out = append(out, cose...)
	}
	return out
}

// create answers a registration challenge.
func (a *softAuth) create(challenge string) string {
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": a.origin})
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(0x45, true)})
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]any{"attestationObject": b64(att), "clientDataJSON": b64(cd)}})
	return string(b)
}

// get answers a login challenge.
func (a *softAuth) get(challenge string, userHandle []byte) string {
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": a.origin})
	ad := a.authData(0x05, false)
	h := sha256.Sum256(cd)
	msg := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, msg[:])
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]any{"authenticatorData": b64(ad), "clientDataJSON": b64(cd), "signature": b64(sig), "userHandle": b64(userHandle)}})
	return string(b)
}

func (e *env) registerPasskey(c *http.Client, a *softAuth, bootstrap string) (int, []byte) {
	e.t.Helper()
	code, b := e.call(c, "POST", "/api/v1/admin/auth/passkey/register/begin", `{"label":"test key","bootstrap_token":"`+bootstrap+`"}`)
	if code != http.StatusOK {
		return code, b
	}
	return e.call(c, "POST", "/api/v1/admin/auth/passkey/register/finish", a.create(challengeOf(e.t, b)))
}

func (e *env) loginPasskey(c *http.Client, a *softAuth) (int, []byte) {
	e.t.Helper()
	code, b := e.call(c, "POST", "/api/v1/admin/auth/passkey/login/begin", "{}")
	if code != http.StatusOK {
		return code, b
	}
	return e.call(c, "POST", "/api/v1/admin/auth/passkey/login/finish", a.get(challengeOf(e.t, b), nil))
}

func TestAdminLoginAndPasskeys(t *testing.T) {
	e := newEnv(t)
	alice := oidctest.User{Subject: "alice", Email: "alice@example.test", Username: "alice", Groups: []string{"vpn-users", "admins"}}
	fake := e.withAdminIdP(t, alice)

	// no credentials: status is "none", the bootstrap token is still alive
	anon := browserClient()
	if st := e.status(anon); st.Level != "none" || !st.BootstrapActive || !st.PasskeysEnabled {
		t.Fatalf("anonymous status: %+v", st)
	}
	if code, _ := e.call(anon, "GET", "/api/v1/admin/nodes", ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous nodes: %d", code)
	}

	// OIDC login of an admin-group member → oidc_only
	c1 := browserClient()
	if code, loc := e.adminLogin(c1, "/nodes"); code != http.StatusFound || loc != "/nodes" {
		t.Fatalf("admin login: %d %s", code, loc)
	}
	if st := e.status(c1); st.Level != "oidc_only" || st.Subject != "alice" || st.Via != "session" {
		t.Fatalf("status after oidc: %+v", st)
	}
	if code, b := e.call(c1, "GET", "/api/v1/admin/nodes", ""); code != http.StatusForbidden || !strings.Contains(string(b), "passkey required") {
		t.Fatalf("oidc_only nodes: %d %s", code, b)
	}
	if code, _ := e.call(c1, "GET", "/api/v1/admin/me", ""); code != http.StatusOK {
		t.Fatalf("oidc_only me: %d", code)
	}

	// the first passkey needs the bootstrap token
	a1 := newSoftAuth(e.admin.URL)
	if code, b := e.registerPasskey(c1, a1, "wrong"); code != http.StatusForbidden {
		t.Fatalf("first passkey without bootstrap token: %d %s", code, b)
	}
	code, b := e.registerPasskey(c1, a1, e.boot)
	if code != http.StatusCreated || !strings.Contains(string(b), `"status":"active"`) {
		t.Fatalf("first passkey: %d %s", code, b)
	}
	if st := e.status(c1); st.Level != "full" || st.OwnActive != 1 || st.BootstrapActive {
		t.Fatalf("status after passkey: %+v", st)
	}
	if code, _ := e.call(c1, "GET", "/api/v1/admin/nodes", ""); code != http.StatusOK {
		t.Fatalf("full nodes: %d", code)
	}

	// the bootstrap token is dead now
	req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/admin/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+e.boot)
	rsp, _ := http.DefaultClient.Do(req)
	bb, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(bb), "bootstrap token is disabled") {
		t.Fatalf("bootstrap after passkey: %d %s", rsp.StatusCode, bb)
	}

	// CSRF: a cookie request without the header is refused
	req, _ = http.NewRequest("POST", e.admin.URL+"/api/v1/admin/tokens", strings.NewReader(`{"name":"x"}`))
	rsp, _ = c1.Do(req)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf: %d", rsp.StatusCode)
	}

	// API tokens: minted by a full admin, full themselves, revocable
	var tok api.TokenView
	code, b = e.call(c1, "POST", "/api/v1/admin/tokens", `{"name":"ci","expires_in":"1h"}`)
	if code != http.StatusCreated || json.Unmarshal(b, &tok) != nil || !strings.HasPrefix(tok.Token, "bgapi_") {
		t.Fatalf("create token: %d %s", code, b)
	}
	bearer := func(token, path string) int {
		req, _ := http.NewRequest("GET", e.admin.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		rsp.Body.Close()
		return rsp.StatusCode
	}
	if code := bearer(tok.Token, "/api/v1/admin/nodes"); code != http.StatusOK {
		t.Fatalf("token nodes: %d", code)
	}
	if code := bearer("bgapi_nope", "/api/v1/admin/nodes"); code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", code)
	}
	if code, _ := e.call(c1, "DELETE", "/api/v1/admin/tokens/"+tok.ID, ""); code != http.StatusNoContent {
		t.Fatalf("revoke token: %d", code)
	}
	if code := bearer(tok.Token, "/api/v1/admin/nodes"); code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", code)
	}

	// logout ends the session; a new OIDC login is oidc_only again and the
	// passkey assertion makes it full
	if code, _ := e.call(c1, "POST", "/api/v1/admin/auth/logout", ""); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := e.call(c1, "GET", "/api/v1/admin/nodes", ""); code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", code)
	}
	c1 = browserClient()
	e.adminLogin(c1, "/")
	if st := e.status(c1); st.Level != "oidc_only" {
		t.Fatalf("relogin: %+v", st)
	}
	wrong := newSoftAuth(e.admin.URL)
	wrong.id = a1.id // right id, wrong key
	if code, b := e.loginPasskey(c1, wrong); code != http.StatusForbidden {
		t.Fatalf("wrong key accepted: %d %s", code, b)
	}
	if code, b := e.loginPasskey(c1, a1); code != http.StatusOK {
		t.Fatalf("passkey login: %d %s", code, b)
	}
	if st := e.status(c1); st.Level != "full" {
		t.Fatalf("after passkey login: %+v", st)
	}

	// a second admin: passkey pending until approved by another admin
	fake.User = oidctest.User{Subject: "bob", Email: "bob@example.test", Username: "bob", Groups: []string{"admins"}}
	c2 := browserClient()
	e.adminLogin(c2, "/")
	a2 := newSoftAuth(e.admin.URL)
	code, b = e.registerPasskey(c2, a2, "")
	if code != http.StatusCreated || !strings.Contains(string(b), `"status":"pending"`) {
		t.Fatalf("second admin passkey: %d %s", code, b)
	}
	var reg struct{ ID string }
	json.Unmarshal(b, &reg)
	if st := e.status(c2); st.Level != "oidc_only" || st.OwnPending != 1 {
		t.Fatalf("bob status: %+v", st)
	}
	if code, b := e.loginPasskey(c2, a2); code != http.StatusConflict || !strings.Contains(string(b), `"pending":1`) {
		t.Fatalf("login with pending passkey: %d %s", code, b)
	}
	if code, _ := e.call(c2, "POST", "/api/v1/admin/passkeys/"+reg.ID+"/approve", ""); code != http.StatusForbidden {
		t.Fatalf("self approval: %d", code)
	}
	var pks []api.PasskeyView
	code, b = e.call(c1, "GET", "/api/v1/admin/passkeys", "")
	if code != http.StatusOK || json.Unmarshal(b, &pks) != nil || len(pks) != 2 {
		t.Fatalf("list passkeys: %d %s", code, b)
	}
	if code, b := e.call(c1, "POST", "/api/v1/admin/passkeys/"+reg.ID+"/approve", ""); code != http.StatusOK || !strings.Contains(string(b), `"approved_by":"alice"`) {
		t.Fatalf("approve: %d %s", code, b)
	}
	if code, b := e.loginPasskey(c2, a2); code != http.StatusOK {
		t.Fatalf("bob passkey login: %d %s", code, b)
	}
	if code, _ := e.call(c2, "GET", "/api/v1/admin/nodes", ""); code != http.StatusOK {
		t.Fatalf("bob full: %d", code)
	}
	// a full admin adds a second passkey for themselves without approval
	a3 := newSoftAuth(e.admin.URL)
	if code, b := e.registerPasskey(c2, a3, ""); code != http.StatusCreated || !strings.Contains(string(b), `"status":"active"`) {
		t.Fatalf("self second passkey: %d %s", code, b)
	}
	// revoking bob's first passkey; his session keeps its level, the next
	// login must use the other key
	if code, _ := e.call(c1, "DELETE", "/api/v1/admin/passkeys/"+reg.ID, ""); code != http.StatusNoContent {
		t.Fatalf("revoke passkey: %d", code)
	}
	c2b := browserClient()
	e.adminLogin(c2b, "/")
	if code, _ := e.loginPasskey(c2b, a2); code != http.StatusForbidden {
		t.Fatalf("revoked passkey login: %d", code)
	}
	if code, _ := e.loginPasskey(c2b, a3); code != http.StatusOK {
		t.Fatalf("other passkey login: %d", code)
	}

	// overview works for full admins
	var ov api.Overview
	code, b = e.call(c1, "GET", "/api/v1/admin/overview", "")
	if code != http.StatusOK || json.Unmarshal(b, &ov) != nil {
		t.Fatalf("overview: %d %s", code, b)
	}

	// audit trail
	if code, b := e.call(c1, "GET", "/api/v1/admin/logs?stream=admin-auth", ""); code != http.StatusOK || !strings.Contains(string(b), "passkey approved") {
		t.Fatalf("audit: %d %s", code, b)
	}
}

func TestAdminLoginRefusals(t *testing.T) {
	e := newEnv(t)
	e.withAdminIdP(t, oidctest.User{Subject: "carol", Email: "carol@example.test", Username: "carol", Groups: []string{"vpn-users"}})
	c := browserClient()
	// not in the admin group
	if code, body := e.adminLogin(c, "/"); code != http.StatusForbidden || !strings.Contains(body, "Not an administrator") {
		t.Fatalf("non-admin login: %d %s", code, body)
	}
	if st := e.status(c); st.Level != "none" {
		t.Fatalf("status: %+v", st)
	}
	// open redirects are not followed
	rsp, _ := c.Get(e.admin.URL + "/api/v1/admin/auth/login?next=//evil.example")
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusFound {
		t.Fatalf("login start: %d", rsp.StatusCode)
	}
	// a callback from a different browser (no flow cookie) is refused
	other := browserClient()
	rsp, _ = c.Get(rsp.Header.Get("Location"))
	rsp.Body.Close()
	rsp, _ = other.Get(rsp.Header.Get("Location"))
	b, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "Wrong browser") {
		t.Fatalf("foreign callback: %d %s", rsp.StatusCode, b)
	}
}
