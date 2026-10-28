package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc/oidctest"
)

// bearer makes one request with a token and returns the status and body.
func (e *env) bearer(token, method, path, body string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.admin.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rsp.Body.Close()
	var b []byte
	if rsp.ContentLength != 0 {
		b = make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := rsp.Body.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
	}
	return rsp.StatusCode, b
}

// What the bootstrap token minted dies with it at the first passkey (R54),
// also what such a token minted in turn: a chain of tokens used to keep
// the bootstrap token's authority alive for good.
func TestTokensMintedUnderTheBootstrapTokenDieWithIt(t *testing.T) {
	e := newEnv(t)
	e.withAdminIdP(t, oidctest.User{Subject: "alice", Email: "alice@example.test", Username: "alice", Groups: []string{"admins"}})

	var t1, t2 api.TokenView
	if code, b := e.bearer(e.boot, "POST", "/api/v1/admin/tokens", `{"name":"t1"}`); code != http.StatusCreated || json.Unmarshal(b, &t1) != nil {
		t.Fatalf("t1: %d %s", code, b)
	}
	if code, b := e.bearer(t1.Token, "POST", "/api/v1/admin/tokens", `{"name":"t2"}`); code != http.StatusCreated || json.Unmarshal(b, &t2) != nil {
		t.Fatalf("t2: %d %s", code, b)
	}
	if !t2.Bootstrap {
		t.Fatalf("a token minted by a bootstrap token does not carry the mark: %+v", t2)
	}
	if code, _ := e.bearer(t2.Token, "GET", "/api/v1/admin/nodes", ""); code != http.StatusOK {
		t.Fatalf("t2 before the first passkey: %d", code)
	}

	c := browserClient()
	e.adminLogin(c, "/")
	if code, b := e.registerPasskey(c, newSoftAuth(e.admin.URL), e.boot); code != http.StatusCreated {
		t.Fatalf("first passkey: %d %s", code, b)
	}
	for name, tok := range map[string]string{"t1": t1.Token, "t2": t2.Token} {
		if code, _ := e.bearer(tok, "GET", "/api/v1/admin/nodes", ""); code != http.StatusUnauthorized {
			t.Errorf("%s after the first passkey: %d", name, code)
		}
	}
}

// "Another admin must approve" (R55) means a person: a token an admin
// minted cannot approve or revoke passkeys. And an admin whose passkeys
// were all revoked does not give themselves a new one that works at once.
func TestPasskeyRulesNeedAPerson(t *testing.T) {
	e := newEnv(t)
	alice := oidctest.User{Subject: "alice", Email: "alice@example.test", Username: "alice", Groups: []string{"admins"}}
	fake := e.withAdminIdP(t, alice)
	c1 := browserClient()
	e.adminLogin(c1, "/")
	a1 := newSoftAuth(e.admin.URL)
	if code, b := e.registerPasskey(c1, a1, e.boot); code != http.StatusCreated {
		t.Fatalf("first passkey: %d %s", code, b)
	}
	var tok api.TokenView
	if code, b := e.call(c1, "POST", "/api/v1/admin/tokens", `{"name":"ci"}`); code != http.StatusCreated || json.Unmarshal(b, &tok) != nil {
		t.Fatalf("token: %d %s", code, b)
	}

	// bob's passkey is pending
	fake.User = oidctest.User{Subject: "bob", Email: "bob@example.test", Username: "bob", Groups: []string{"admins"}}
	c2 := browserClient()
	e.adminLogin(c2, "/")
	a2 := newSoftAuth(e.admin.URL)
	code, b := e.registerPasskey(c2, a2, "")
	if code != http.StatusCreated || !strings.Contains(string(b), `"status":"pending"`) {
		t.Fatalf("bob's passkey: %d %s", code, b)
	}
	var reg struct{ ID string }
	_ = json.Unmarshal(b, &reg)

	// alice's token may neither approve it nor revoke alice's own
	if code, b := e.bearer(tok.Token, "POST", "/api/v1/admin/passkeys/"+reg.ID+"/approve", ""); code != http.StatusForbidden {
		t.Fatalf("approval by a token: %d %s", code, b)
	}
	var pks []api.PasskeyView
	_, b = e.call(c1, "GET", "/api/v1/admin/passkeys", "")
	_ = json.Unmarshal(b, &pks)
	var aliceKey string
	for _, p := range pks {
		if p.Subject == "alice" {
			aliceKey = p.ID
		}
	}
	if code, b := e.bearer(tok.Token, "DELETE", "/api/v1/admin/passkeys/"+aliceKey, ""); code != http.StatusForbidden {
		t.Fatalf("revocation by a token: %d %s", code, b)
	}
	// alice herself does
	if code, b := e.call(c1, "POST", "/api/v1/admin/passkeys/"+reg.ID+"/approve", ""); code != http.StatusOK {
		t.Fatalf("approval by alice: %d %s", code, b)
	}

	// bob (full now) revokes alice's only passkey: her session keeps its
	// level, but a new passkey of hers waits for an approval
	if code, b := e.loginPasskey(c2, a2); code != http.StatusOK {
		t.Fatalf("bob's login: %d %s", code, b)
	}
	if code, _ := e.call(c2, "DELETE", "/api/v1/admin/passkeys/"+aliceKey, ""); code != http.StatusNoContent {
		t.Fatalf("bob revokes alice's passkey: %d", code)
	}
	if st := e.status(c1); st.Level != "full" || st.OwnActive != 0 {
		t.Fatalf("alice after the revocation: %+v", st)
	}
	code, b = e.registerPasskey(c1, newSoftAuth(e.admin.URL), "")
	if code != http.StatusCreated || !strings.Contains(string(b), `"status":"pending"`) {
		t.Fatalf("alice's replacement passkey: %d %s", code, b)
	}
}
