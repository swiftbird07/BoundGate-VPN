package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/snapshot"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicecert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/servercert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

type env struct {
	t        *testing.T
	store    *db.DB
	boot     string
	admin    *httptest.Server
	node     *httptest.Server
	roots    *x509.CertPool
	handlers *api.Handlers
	signer   ssh.Signer // the registered admin key
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(dir, "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	boot, _, err := store.EnsureBootstrapToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	logs, err := logging.Open(logging.Options{Dir: filepath.Join(dir, "logs")})
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(api.Deps{DB: store, Snap: snapshot.New(store), Logs: logs})

	cert, _, err := servercert.LoadOrCreate(filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key"), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)

	e := &env{t: t, store: store, boot: boot, roots: roots, handlers: h}
	e.admin = httptest.NewServer(h.AdminMux())
	e.node = httptest.NewUnstartedServer(h.NodeMux())
	e.node.TLS = transport.ServerTLSConfigAnyDevice(cert)
	e.node.StartTLS()
	t.Cleanup(func() { e.admin.Close(); e.node.Close() })
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.signer, _ = ssh.NewSignerFromKey(priv)
	return e
}

// registerSigner adds the env's admin key (a software ed25519 key; the
// format is the same for sk-keys).
func (e *env) registerSigner() api.SignerView {
	e.t.Helper()
	var sv api.SignerView
	e.adminCall("POST", "/api/v1/admin/signers", `{"name":"test admin","public_key":"`+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.signer.PublicKey())))+`"}`, http.StatusCreated, &sv)
	return sv
}

// signCall uses a sign token instead of the admin token.
func (e *env) signCall(token, method, path, body string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.admin.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	return rsp.StatusCode, b
}

// signWith fetches the binding for token, signs it with signer and posts it.
func (e *env) signWith(token string, signer ssh.Signer) (int, []byte) {
	e.t.Helper()
	code, b := e.signCall(token, "GET", "/api/v1/sign/binding", "")
	if code != http.StatusOK {
		return code, b
	}
	var sb api.SignBinding
	if err := json.Unmarshal(b, &sb); err != nil {
		e.t.Fatal(err)
	}
	sig, err := binding.Sign(signer, sb.Namespace, []byte(sb.Binding))
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := json.Marshal(api.SignatureBody{Signature: sig})
	return e.signCall(token, "POST", "/api/v1/sign/signature", string(body))
}

// approve runs confirm + sign for a node with the given grant.
func (e *env) approve(id, grant string) api.NodeView {
	e.t.Helper()
	var cr api.ConfirmResponse
	e.adminCall("POST", "/api/v1/admin/nodes/"+id+"/confirm", grant, http.StatusOK, &cr)
	if cr.SignToken == "" {
		e.t.Fatalf("no sign token: %+v", cr)
	}
	code, b := e.signWith(cr.SignToken, e.signer)
	if code != http.StatusOK {
		e.t.Fatalf("sign: %d %s", code, b)
	}
	var nv api.NodeView
	_ = json.Unmarshal(b, &nv)
	return nv
}

func (e *env) adminCall(method, path, body string, want int, out any) []byte {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.admin.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.boot)
	req.Header.Set("Content-Type", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	if rsp.StatusCode != want {
		e.t.Fatalf("%s %s: got %d want %d: %s", method, path, rsp.StatusCode, want, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("decode: %v: %s", err, b)
		}
	}
	return b
}

type dev struct {
	c    *http.Client
	spki string
}

func (e *env) device(name string) dev {
	e.t.Helper()
	key, err := softkey.New(filepath.Join(e.t.TempDir(), "k")).Open(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	cert, err := devicecert.SelfSigned(key, name)
	if err != nil {
		e.t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: e.roots}}}
	st := &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert.Leaf}}
	h, _ := transport.UnverifiedSPKI(st)
	return dev{c: c, spki: h.String()}
}

func (e *env) nodeCall(d dev, method, path, body string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.node.URL+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rsp, err := d.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	return rsp.StatusCode, b
}

func (e *env) snapshot(d dev, since uint64, wait string) (int, *registry.Snapshot) {
	e.t.Helper()
	code, b := e.nodeCall(d, "GET", "/api/v1/node/snapshot?since="+strconv.FormatUint(since, 10)+"&wait="+wait, "")
	if code != http.StatusOK {
		return code, nil
	}
	var s registry.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		e.t.Fatal(err)
	}
	s.Index()
	return code, &s
}

func (e *env) enroll(d dev, body string) api.EnrollStatus {
	e.t.Helper()
	code, b := e.nodeCall(d, "POST", "/api/v1/node/enroll", body)
	if code != http.StatusAccepted && code != http.StatusOK {
		e.t.Fatalf("enroll: %d %s", code, b)
	}
	var st api.EnrollStatus
	_ = json.Unmarshal(b, &st)
	return st
}

func mustSPKI(t *testing.T, s string) devicekey.SPKIHash {
	t.Helper()
	h, err := devicekey.ParseSPKIHash(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestEnrollmentApprovalRevocationFlow(t *testing.T) {
	e := newEnv(t)
	a := e.device("laptop")
	hub := e.device("hub1")

	// unknown node: status is unknown, protected routes are 403
	code, body := e.nodeCall(a, "GET", "/api/v1/node/enroll/status", "")
	if code != http.StatusNotFound || !strings.Contains(string(body), `"unknown"`) {
		t.Fatalf("status before enroll: %d %s", code, body)
	}
	if code, _ := e.snapshot(a, 0, "1s"); code != http.StatusForbidden {
		t.Fatalf("unapproved node reached /snapshot: %d", code)
	}

	// without an admin signing key nobody can enroll
	if code, b := e.nodeCall(a, "POST", "/api/v1/node/enroll", `{"roles":["endpoint"]}`); code != http.StatusServiceUnavailable {
		t.Fatalf("enroll without signers: %d %s", code, b)
	}
	sv := e.registerSigner()
	if sv.Hardware || sv.KeyType != "ssh-ed25519" || sv.Fingerprint != ssh.FingerprintSHA256(e.signer.PublicKey()) {
		t.Fatalf("%+v", sv)
	}

	// enroll -> pending, with requested roles and prefixes; the node learns
	// the admin keys and the control key to pin
	st := e.enroll(a, `{"name":"laptop","platform":"linux","key_kind":"softkey","roles":["endpoint","subnet-router"],"prefixes":[{"prefix":"192.168.178.0/24","mode":"snat"}]}`)
	if st.Status != "pending" || st.NodeID == "" || st.OverlayIP != "" || len(st.AdminSignerKeys) != 1 || !strings.HasPrefix(st.AdminSignerKeys[0], "ssh-ed25519 ") {
		t.Fatalf("%+v", st)
	}
	if again := e.enroll(a, `{}`); again.NodeID != st.NodeID || again.Status != "pending" {
		t.Fatalf("re-enroll not idempotent: %+v", again)
	}
	var nv api.NodeView
	e.adminCall("GET", "/api/v1/admin/nodes/"+st.NodeID, "", http.StatusOK, &nv)
	if len(nv.RequestedRoles) != 2 || len(nv.RequestedPrefixes) != 1 || len(nv.Roles) != 0 {
		t.Fatalf("%+v", nv)
	}

	// confirm: wrong fingerprint 409, no roles 400, then ok with overlay assigned and a sign token
	e.adminCall("POST", "/api/v1/admin/nodes/"+st.NodeID+"/confirm", `{"fingerprint":"deadbeef","roles":["endpoint"]}`, http.StatusConflict, nil)
	e.adminCall("POST", "/api/v1/admin/nodes/"+st.NodeID+"/confirm", `{"fingerprint":"`+a.spki+`"}`, http.StatusBadRequest, nil)
	var cr api.ConfirmResponse
	e.adminCall("POST", "/api/v1/admin/nodes/"+st.NodeID+"/confirm",
		`{"fingerprint":"`+a.spki+`","name":"martins-laptop","roles":["endpoint","subnet-router"],"prefixes":[{"prefix":"192.168.178.0/24","mode":"snat"}]}`, http.StatusOK, &cr)
	if cr.Status != "confirmed" || cr.Name != "martins-laptop" || cr.ConfirmedBy != "bootstrap" || cr.OverlayIP != "10.21.0.1" || len(cr.Prefixes) != 1 || cr.Signed ||
		!strings.HasPrefix(cr.SignToken, "bgsign_") || !strings.Contains(cr.SignCommand, "--fingerprint "+a.spki) || !strings.Contains(cr.SignCommand, cr.SignToken) {
		t.Fatalf("%+v", cr)
	}
	// confirmed is not approved: no snapshot, still status confirmed
	if code, _ := e.snapshot(a, 0, "300ms"); code != http.StatusForbidden {
		t.Fatalf("confirmed node reached /snapshot: %d", code)
	}
	if es := e.enroll(a, `{}`); es.Status != "confirmed" {
		t.Fatalf("%+v", es)
	}

	// sign: unknown token 401, stranger key 403, wrong content 409, then ok
	if code, _ := e.signCall("bgsign_nope", "GET", "/api/v1/sign/binding", ""); code != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", code)
	}
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	stranger, _ := ssh.NewSignerFromKey(strangerPriv)
	if code, b := e.signWith(cr.SignToken, stranger); code != http.StatusForbidden {
		t.Fatalf("stranger signature: %d %s", code, b)
	}
	{
		sig, _ := binding.Sign(e.signer, binding.Namespace, []byte(`{"node_id":"other"}`))
		body, _ := json.Marshal(api.SignatureBody{Signature: sig})
		if code, b := e.signCall(cr.SignToken, "POST", "/api/v1/sign/signature", string(body)); code != http.StatusConflict {
			t.Fatalf("signature over other content: %d %s", code, b)
		}
	}
	code, body = e.signWith(cr.SignToken, e.signer)
	if code != http.StatusOK {
		t.Fatalf("sign: %d %s", code, body)
	}
	_ = json.Unmarshal(body, &nv)
	if nv.Status != "approved" || !nv.Signed || nv.SignedBy != sv.Fingerprint || nv.ApprovedBy != sv.Fingerprint || nv.OverlayIP != "10.21.0.1" {
		t.Fatalf("%+v", nv)
	}
	// the token is single use
	if code, b := e.signWith(cr.SignToken, e.signer); code != http.StatusConflict {
		t.Fatalf("token reuse: %d %s", code, b)
	}

	// the node's own snapshot: self record with a verifiable binding, no peers yet
	code, snap := e.snapshot(a, 0, "1s")
	if code != http.StatusOK || string(snap.Self.ID) != st.NodeID || snap.Self.OverlayIP.String() != "10.21.0.1" || len(snap.Peers) != 0 || len(snap.Self.Prefixes) != 1 {
		t.Fatalf("snapshot: %d %+v", code, snap)
	}
	if _, err := binding.VerifyNode(snap.Self, binding.Signers{e.signer.PublicKey()}); err != nil {
		t.Fatalf("self binding: %v", err)
	}
	v0 := snap.Version
	if code, _ := e.snapshot(a, v0, "300ms"); code != http.StatusNotModified {
		t.Fatalf("unchanged snapshot: %d", code)
	}

	// long-poll waits and wakes up when a hub is approved
	done := make(chan *registry.Snapshot, 1)
	go func() {
		_, s := e.snapshot(a, v0, "10s")
		done <- s
	}()
	time.Sleep(100 * time.Millisecond)
	hst := e.enroll(hub, `{"name":"hub1","roles":["hub"],"public_addr":"hub1:443"}`)
	nv = e.approve(hst.NodeID, `{"roles":["hub","subnet-router"],"prefixes":[{"prefix":"10.60.0.0/24","mode":"routed"}]}`)
	if nv.PublicAddr != "hub1:443" || nv.OverlayIP != "10.21.0.2" || nv.Status != "approved" {
		t.Fatalf("%+v", nv)
	}
	select {
	case s := <-done:
		if s == nil || len(s.Peers) != 1 || s.Peers[0].SPKI.String() != hub.spki || !s.Peers[0].IsHub() || len(s.Hubs()) != 1 || s.Version <= v0 {
			t.Fatalf("long-poll snapshot: %+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll did not wake up on approval")
	}
	// the hub sees the laptop as a peer with its prefix, itself as self
	_, hs := e.snapshot(hub, 0, "1s")
	if hs == nil || string(hs.Self.ID) != hst.NodeID || len(hs.Peers) != 1 || string(hs.Peers[0].ID) != st.NodeID || len(hs.Peers[0].Prefixes) != 1 || len(hs.Hubs()) != 0 {
		t.Fatalf("hub snapshot: %+v", hs)
	}
	if _, ok := hs.LookupSPKI(mustSPKI(t, a.spki)); !ok {
		t.Fatal("hub snapshot does not admit the laptop")
	}

	// an unsigned field (name) changes: still approved, snapshot bumped
	before := hs.Version
	var renamed api.ConfirmResponse
	e.adminCall("PATCH", "/api/v1/admin/nodes/"+st.NodeID, `{"name":"laptop-2"}`, http.StatusOK, &renamed)
	if renamed.Status != "approved" || renamed.Name != "laptop-2" || renamed.SignToken != "" {
		t.Fatalf("%+v", renamed)
	}
	_, hs = e.snapshot(hub, before, "1s")
	if hs == nil || hs.Version <= before || len(hs.Peers) != 1 || hs.Peers[0].Name != "laptop-2" {
		t.Fatalf("renamed snapshot: %+v", hs)
	}
	// a signed field (prefixes) changes: the node drops to confirmed, leaves
	// the hub's snapshot and needs a new signature; then it is back
	before = hs.Version
	var demoted api.ConfirmResponse
	e.adminCall("PATCH", "/api/v1/admin/nodes/"+st.NodeID, `{"prefixes":[]}`, http.StatusOK, &demoted)
	if demoted.Status != "confirmed" || len(demoted.Prefixes) != 0 || demoted.Signed || demoted.SignToken == "" || demoted.SignToken == cr.SignToken {
		t.Fatalf("%+v", demoted)
	}
	_, hs = e.snapshot(hub, before, "1s")
	if hs == nil || hs.Version <= before || len(hs.Peers) != 0 {
		t.Fatalf("demoted node still in the hub's snapshot: %+v", hs)
	}
	if code, _ := e.snapshot(a, 0, "300ms"); code != http.StatusForbidden {
		t.Fatalf("demoted node still served: %d", code)
	}
	before = hs.Version
	if code, b := e.signWith(demoted.SignToken, e.signer); code != http.StatusOK {
		t.Fatalf("re-sign: %d %s", code, b)
	}
	_, hs = e.snapshot(hub, before, "1s")
	if hs == nil || len(hs.Peers) != 1 || len(hs.Peers[0].Prefixes) != 0 {
		t.Fatalf("re-signed snapshot: %+v", hs)
	}
	if _, err := binding.VerifyNode(hs.Peers[0], binding.Signers{e.signer.PublicKey()}); err != nil {
		t.Fatalf("peer binding after re-sign: %v", err)
	}
	// the admin snapshot view carries the signed bindings too
	var global registry.Snapshot
	e.adminCall("GET", "/api/v1/admin/snapshot", "", http.StatusOK, &global)
	if len(global.Peers) != 2 || global.Peers[0].Signature == "" {
		t.Fatalf("%+v", global)
	}
	// signers: list, second registration is a conflict, revoked key stops signing
	var signers []api.SignerView
	e.adminCall("GET", "/api/v1/admin/signers", "", http.StatusOK, &signers)
	if len(signers) != 1 || signers[0].ID != sv.ID {
		t.Fatalf("%+v", signers)
	}
	e.adminCall("POST", "/api/v1/admin/signers", `{"public_key":"`+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.signer.PublicKey())))+`"}`, http.StatusConflict, nil)
	e.adminCall("POST", "/api/v1/admin/signers", `{"public_key":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0 x"}`, http.StatusBadRequest, nil)
	if code, b := e.nodeCall(hub, "POST", "/api/v1/node/heartbeat", `{"version":`+strconv.FormatUint(hs.Version, 10)+`,"active_tunnels":3}`); code != http.StatusNoContent {
		t.Fatalf("heartbeat: %d %s", code, b)
	}
	e.adminCall("GET", "/api/v1/admin/nodes/"+hst.NodeID, "", http.StatusOK, &nv)
	if nv.ActiveTunnels != 3 || nv.SnapshotVersion != hs.Version || nv.LastSeenAt == nil {
		t.Fatalf("%+v", nv)
	}

	// pool change that strands an address is refused
	e.adminCall("PUT", "/api/v1/admin/settings/network", `{"pool":"10.99.0.0/24"}`, http.StatusConflict, nil)

	// revoke the laptop: it is gone from the hub's snapshot and gets 403 itself
	e.adminCall("DELETE", "/api/v1/admin/nodes/"+st.NodeID, "", http.StatusNoContent, nil)
	if code, _ := e.snapshot(a, 0, "1s"); code != http.StatusForbidden {
		t.Fatalf("revoked node still served: %d", code)
	}
	_, hs = e.snapshot(hub, 0, "1s")
	if hs == nil || len(hs.Peers) != 0 {
		t.Fatalf("revoked node still a peer: %+v", hs)
	}
	if again := e.enroll(a, `{}`); again.Status != "revoked" {
		t.Fatalf("revoked key re-enrolled: %+v", again)
	}
	e.adminCall("DELETE", "/api/v1/admin/nodes/"+st.NodeID, "", http.StatusConflict, nil)

	// with the only signer revoked, confirm refuses and enrollment is closed
	e.adminCall("DELETE", "/api/v1/admin/signers/"+sv.ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/signers/"+sv.ID, "", http.StatusNotFound, nil)
	d3 := e.device("later")
	if code, _ := e.nodeCall(d3, "POST", "/api/v1/node/enroll", `{"roles":["endpoint"]}`); code != http.StatusServiceUnavailable {
		t.Fatalf("enroll after last signer revoked: %d", code)
	}

	// audit trail
	var evs []db.LogEvent
	e.adminCall("GET", "/api/v1/admin/logs?stream=enrollment&node="+st.NodeID, "", http.StatusOK, &evs)
	msgs := make([]string, 0, len(evs))
	for _, ev := range evs {
		msgs = append(msgs, ev.Message)
	}
	joined := strings.Join(msgs, ",")
	for _, want := range []string{"enrollment requested", "node confirmed", "node approved", "node revoked"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("audit trail lacks %q: %v", want, msgs)
		}
	}
}

func TestRejectPendingAndAuth(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	d := e.device("x")
	st := e.enroll(d, `{"name":"x","roles":["endpoint"]}`)
	e.adminCall("POST", "/api/v1/admin/nodes/"+st.NodeID+"/reject", "", http.StatusNoContent, nil)
	e.adminCall("GET", "/api/v1/admin/nodes/"+st.NodeID, "", http.StatusNotFound, nil)
	if code, _ := e.nodeCall(d, "GET", "/api/v1/node/enroll/status", ""); code != http.StatusNotFound {
		t.Fatalf("rejected node status: %d", code)
	}

	// admin auth: no token, wrong token
	for _, tok := range []string{"", "Bearer nope"} {
		req, _ := http.NewRequest("GET", e.admin.URL+"/api/v1/admin/nodes", nil)
		if tok != "" {
			req.Header.Set("Authorization", tok)
		}
		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		rsp.Body.Close()
		if rsp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", tok, rsp.StatusCode)
		}
	}
	// node API without a client certificate fails in the handshake
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots}}}
	if _, err := c.Get(e.node.URL + "/api/v1/node/enroll/status"); err == nil {
		t.Fatal("node API accepted a connection without a device certificate")
	}
	// unknown role is refused at enrollment
	d2 := e.device("y")
	if code, _ := e.nodeCall(d2, "POST", "/api/v1/node/enroll", `{"roles":["root"]}`); code != http.StatusBadRequest {
		t.Fatalf("unknown role: %d", code)
	}
}

func TestEnrollRateLimit(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	var last int
	for i := 0; i < 7; i++ {
		d := e.device("n")
		last, _ = e.nodeCall(d, "POST", "/api/v1/node/enroll", `{"roles":["endpoint"]}`)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("rate limit not applied: %d", last)
	}
}
