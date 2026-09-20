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
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc/oidctest"
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
	logs     *logging.Streams
	signer   ssh.Signer // the registered admin key
	dbPath   string
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

	e := &env{t: t, store: store, boot: boot, roots: roots, handlers: h, logs: logs, dbPath: filepath.Join(dir, "c.db")}
	e.admin = httptest.NewServer(h.AdminMux())
	e.node = httptest.NewUnstartedServer(h.NodeMux())
	e.node.TLS = transport.ServerTLSConfigAnyDevice(cert)
	e.node.StartTLS()
	t.Cleanup(func() { e.admin.Close(); e.node.Close() })
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.signer, _ = ssh.NewSignerFromKey(priv)
	return e
}

// registerSigner puts the env's admin key (a software ed25519 key; the
// format is the same for sk-keys) into the signed admin key list: proposed
// through the admin API, signed by the key itself as the first list.
func (e *env) registerSigner() api.SignerView {
	e.t.Helper()
	var ch api.SignerChangeView
	e.adminCall("POST", "/api/v1/admin/signers", `{"name":"test admin","public_key":"`+authorizedKey(e.signer)+`"}`, http.StatusAccepted, &ch)
	if code, b := e.signSigners(ch.SignToken, e.signer, binding.SignersNamespace); code != http.StatusOK {
		e.t.Fatalf("sign first admin key list: %d %s", code, b)
	}
	return e.signerByKey(e.signer)
}

func authorizedKey(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

func (e *env) signerByKey(s ssh.Signer) api.SignerView {
	e.t.Helper()
	var all []api.SignerView
	e.adminCall("GET", "/api/v1/admin/signers", "", http.StatusOK, &all)
	for _, v := range all {
		if v.Fingerprint == ssh.FingerprintSHA256(s.PublicKey()) {
			return v
		}
	}
	e.t.Fatalf("key %s is not in the directory", ssh.FingerprintSHA256(s.PublicKey()))
	return api.SignerView{}
}

// signSigners fetches the proposed list for token, signs it with signer in
// namespace ns and posts the signature.
func (e *env) signSigners(token string, signer ssh.Signer, ns string) (int, []byte) {
	e.t.Helper()
	code, b := e.signCall(token, "GET", "/api/v1/sign/signers", "")
	if code != http.StatusOK {
		return code, b
	}
	var p api.SignSigners
	if err := json.Unmarshal(b, &p); err != nil {
		e.t.Fatal(err)
	}
	sig, err := binding.Sign(signer, ns, []byte(p.Set))
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := json.Marshal(api.SignatureBody{Signature: sig})
	return e.signCall(token, "POST", "/api/v1/sign/signers", string(body))
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
	if tr, err := binding.VerifyChain(binding.Trust{}, st.SignerChain, ""); err != nil || tr.Version != 1 || len(tr.Keys) != 1 || tr.Keys[0] != authorizedKey(e.signer) {
		t.Fatalf("enroll status carries no verifiable admin key list: %+v %v", tr, err)
	}
	if st.Status != "pending" || st.NodeID == "" || st.OverlayIP != "" {
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
	e.adminCall("POST", "/api/v1/admin/signers", `{"public_key":"`+authorizedKey(e.signer)+`"}`, http.StatusConflict, nil)
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

	// the last key cannot be removed, and an unknown id is not a key of the list
	e.adminCall("DELETE", "/api/v1/admin/signers/"+sv.ID, "", http.StatusConflict, nil)
	e.adminCall("DELETE", "/api/v1/admin/signers/nope", "", http.StatusNotFound, nil)

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

// withIdP attaches a fake identity provider to the env.
func (e *env) withIdP(t *testing.T, lifetime time.Duration) *oidctest.Provider {
	t.Helper()
	fake := oidctest.New("", "bg", "secret", oidctest.User{Subject: "u1", Email: "martin@example.test", Username: "martin", Groups: []string{"vpn-users"}})
	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)
	fake.Issuer = srv.URL
	e.handlers = api.New(api.Deps{DB: e.store, Snap: snapshot.New(e.store), Logs: e.logs,
		OIDC: oidc.NewLazy(oidc.Config{Issuer: srv.URL, ClientID: "bg", ClientSecret: "secret", RedirectURL: e.admin.URL + "/api/v1/oidc/callback", SessionLifetime: lifetime})})
	e.admin.Config.Handler = e.handlers.AdminMux()
	e.node.Config.Handler = e.handlers.NodeMux()
	return fake
}

// browser follows the IdP redirect and calls the control plane's callback.
func (e *env) browser(t *testing.T, authURL string) (int, string) {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rsp, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	loc := rsp.Header.Get("Location")
	if rsp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, e.admin.URL+"/api/v1/oidc/callback?") {
		t.Fatalf("authorize: %d %s", rsp.StatusCode, loc)
	}
	rsp, err = http.Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	return rsp.StatusCode, string(b)
}

func TestUserLoginFlow(t *testing.T) {
	e := newEnv(t)
	e.withIdP(t, 2*time.Second)
	e.registerSigner()
	laptop := e.device("laptop")
	hub := e.device("hub")
	// login before approval: 403 like everything else
	if code, _ := e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}"); code != http.StatusForbidden {
		t.Fatalf("login before approval: %d", code)
	}
	lst := e.enroll(laptop, `{"name":"laptop","roles":["endpoint"]}`)
	e.approve(lst.NodeID, `{"roles":["endpoint"]}`) // interactive by default
	hst := e.enroll(hub, `{"name":"hub","roles":["hub"],"public_addr":"hub:443"}`)
	hv := e.approve(hst.NodeID, `{"kind":"workload","roles":["hub"]}`)
	if hv.Kind != "workload" {
		t.Fatalf("%+v", hv)
	}
	_, snap := e.snapshot(laptop, 0, "1s")
	if snap.Self.Kind != registry.KindInteractive || !snap.Self.NeedsSession() || len(snap.Sessions) != 0 {
		t.Fatalf("%+v", snap.Self)
	}

	// start a flow, "browser" completes it, node sees the session
	code, b := e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
	if code != http.StatusOK {
		t.Fatalf("login start: %d %s", code, b)
	}
	var ls api.LoginStart
	_ = json.Unmarshal(b, &ls)
	if ls.FlowID == "" || !strings.Contains(ls.URL, "/authorize?") {
		t.Fatalf("%+v", ls)
	}
	code, b = e.nodeCall(laptop, "GET", "/api/v1/node/login/"+ls.FlowID+"?wait=0s", "")
	var st api.LoginStatus
	_ = json.Unmarshal(b, &st)
	if code != http.StatusOK || st.Status != "pending" {
		t.Fatalf("%d %+v", code, st)
	}
	// another node cannot read the flow
	if code, _ := e.nodeCall(hub, "GET", "/api/v1/node/login/"+ls.FlowID, ""); code != http.StatusNotFound {
		t.Fatalf("foreign flow readable: %d", code)
	}
	code, page := e.browser(t, ls.URL)
	if code != http.StatusOK || !strings.Contains(page, "Logged in") || !strings.Contains(page, "martin") {
		t.Fatalf("callback: %d %s", code, page)
	}
	code, b = e.nodeCall(laptop, "GET", "/api/v1/node/login/"+ls.FlowID+"?wait=0s", "")
	_ = json.Unmarshal(b, &st)
	if code != http.StatusOK || st.Status != "done" || st.Session == nil || st.Session.Subject != "u1" || st.Session.NodeID != lst.NodeID || len(st.Session.Groups) != 1 {
		t.Fatalf("%d %+v", code, st)
	}
	// replaying the callback fails; the code was consumed and the flow is done
	if code, _ := e.browser(t, ls.URL); code != http.StatusForbidden && code != http.StatusConflict {
		t.Fatalf("callback replay: %d", code)
	}
	// the session is in the laptop's and the hub's snapshot, bound to the laptop
	_, snap = e.snapshot(laptop, 0, "1s")
	se, ok := snap.SessionFor(snap.Self.ID, time.Now())
	if !ok || se.Subject != "u1" || se.Username != "martin" {
		t.Fatalf("own session missing: %+v", snap.Sessions)
	}
	_, hs := e.snapshot(hub, 0, "1s")
	if _, ok := hs.SessionFor(transport.DeviceID(lst.NodeID), time.Now()); !ok {
		t.Fatalf("hub does not see the laptop's session: %+v", hs.Sessions)
	}
	if _, ok := hs.SessionFor(hs.Self.ID, time.Now()); ok {
		t.Fatal("hub has a session")
	}
	// admin sees it and can revoke it: gone from snapshots at once
	var sessions []api.SessionView
	e.adminCall("GET", "/api/v1/admin/sessions", "", http.StatusOK, &sessions)
	if len(sessions) != 1 || sessions[0].NodeName != "laptop" || sessions[0].Username != "martin" {
		t.Fatalf("%+v", sessions)
	}
	before := hs.Version
	e.adminCall("DELETE", "/api/v1/admin/sessions/"+sessions[0].ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/sessions/"+sessions[0].ID, "", http.StatusConflict, nil)
	_, hs = e.snapshot(hub, before, "1s")
	if hs == nil || len(hs.Sessions) != 0 {
		t.Fatalf("revoked session still distributed: %+v", hs)
	}
	e.adminCall("GET", "/api/v1/admin/sessions?all=1", "", http.StatusOK, &sessions)
	if len(sessions) != 1 || sessions[0].EndReason != "revoked" || sessions[0].EndedBy != "bootstrap" {
		t.Fatalf("%+v", sessions)
	}

	// login again, then logout by the node; a second login replaces the first
	code, b = e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
	_ = json.Unmarshal(b, &ls)
	e.browser(t, ls.URL)
	code, b = e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
	_ = json.Unmarshal(b, &ls)
	e.browser(t, ls.URL)
	e.adminCall("GET", "/api/v1/admin/sessions", "", http.StatusOK, &sessions)
	if len(sessions) != 1 {
		t.Fatalf("two active sessions for one node: %+v", sessions)
	}
	if code, _ := e.nodeCall(laptop, "POST", "/api/v1/node/logout", "{}"); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	e.adminCall("GET", "/api/v1/admin/sessions", "", http.StatusOK, &sessions)
	if len(sessions) != 0 {
		t.Fatalf("session after logout: %+v", sessions)
	}

	// expiry: a 2 s session disappears from the snapshot (SessionFor) and,
	// after the sweep, from the database
	code, b = e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
	_ = json.Unmarshal(b, &ls)
	if code, body := e.browser(t, ls.URL); code != http.StatusOK {
		t.Fatalf("second login: %d %s (start: %s)", code, body, b)
	}
	_, snap = e.snapshot(laptop, 0, "1s")
	if _, ok := snap.SessionFor(snap.Self.ID, time.Now().Add(3*time.Second)); ok {
		t.Fatal("expired session accepted")
	}
	// wait on the wall clock, not on a sleep: expiry compares wall-clock
	// timestamps and a VM's clock may be slewed while we sleep
	if ss, err := e.store.ActiveSessions(context.Background()); err == nil && len(ss) == 1 {
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(ss[0].ExpiresAt.Add(20*time.Millisecond)) && time.Now().Before(deadline); {
			time.Sleep(50 * time.Millisecond)
		}
	} else {
		time.Sleep(2100 * time.Millisecond)
	}
	n, _, err := e.store.ExpireSessions(context.Background())
	if err != nil || n != 1 {
		e.adminCall("GET", "/api/v1/admin/sessions?all=1", "", http.StatusOK, &sessions)
		t.Fatalf("expire: %d %v at %s: %+v", n, err, time.Now().UTC().Format(time.RFC3339Nano), sessions)
	}
	e.adminCall("GET", "/api/v1/admin/sessions?all=1", "", http.StatusOK, &sessions)
	if sessions[0].EndReason != "expired" {
		t.Fatalf("%+v", sessions[0])
	}

	// refusal at the IdP and an unknown state
	code, b = e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
	_ = json.Unmarshal(b, &ls)
	if code, page := e.browser(t, ls.URL+"&deny=1"); code != http.StatusForbidden || !strings.Contains(page, "refused") {
		t.Fatalf("deny: %d %s", code, page)
	}
	code, b = e.nodeCall(laptop, "GET", "/api/v1/node/login/"+ls.FlowID+"?wait=0s", "")
	_ = json.Unmarshal(b, &st)
	if st.Status != "failed" || !strings.Contains(st.Error, "access_denied") {
		t.Fatalf("%+v", st)
	}
	if rsp, _ := http.Get(e.admin.URL + "/api/v1/oidc/callback?state=nope&code=x"); rsp == nil || rsp.StatusCode != http.StatusBadRequest {
		t.Fatal("unknown state accepted")
	}

	// a changed kind is a signed field: demotes and needs a new signature
	var demoted api.ConfirmResponse
	e.adminCall("PATCH", "/api/v1/admin/nodes/"+lst.NodeID, `{"kind":"workload"}`, http.StatusOK, &demoted)
	if demoted.Status != "confirmed" || demoted.Kind != "workload" || demoted.SignToken == "" {
		t.Fatalf("%+v", demoted)
	}
	// audit trail
	var evs []db.LogEvent
	e.adminCall("GET", "/api/v1/admin/logs?stream=user-auth&node="+lst.NodeID, "", http.StatusOK, &evs)
	msgs := ""
	for _, ev := range evs {
		msgs += ev.Message + ","
	}
	for _, want := range []string{"login started", "login completed", "session revoked", "logout", "login failed"} {
		if !strings.Contains(msgs, want) {
			t.Fatalf("user-auth log lacks %q: %s", want, msgs)
		}
	}
}

func TestLoginDisabledWithoutIdP(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	d := e.device("x")
	st := e.enroll(d, `{"roles":["endpoint"]}`)
	e.approve(st.NodeID, `{"roles":["endpoint"]}`)
	if code, b := e.nodeCall(d, "POST", "/api/v1/node/login/start", "{}"); code != http.StatusServiceUnavailable {
		t.Fatalf("login without idp: %d %s", code, b)
	}
}

// hardware_bound: the node claims, the admin grants, the binding carries it.
func TestHardwareBoundGrant(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	view := func(id string) api.NodeView {
		var nv api.NodeView
		e.adminCall("GET", "/api/v1/admin/nodes/"+id, "", http.StatusOK, &nv)
		return nv
	}

	// a TPM node: the claim is shown but grants nothing until an admin confirms
	tpm := e.device("server")
	st := e.enroll(tpm, `{"name":"server","platform":"linux","key_kind":"tpm2","hardware_bound":true,"roles":["endpoint"]}`)
	if nv := view(st.NodeID); !nv.HardwareClaimed || nv.HardwareBound {
		t.Fatalf("pending: claimed=%v bound=%v", nv.HardwareClaimed, nv.HardwareBound)
	}
	nv := e.approve(st.NodeID, `{"roles":["endpoint"],"kind":"workload"}`)
	if !nv.HardwareBound || !nv.Signed {
		t.Fatalf("approved: %+v", nv)
	}
	code, snap := e.snapshot(tpm, 0, "1s")
	if code != http.StatusOK || !snap.Self.HardwareBound || !strings.Contains(snap.Self.Binding, `"hardware_bound":true`) {
		t.Fatalf("snapshot: %d %+v", code, snap)
	}

	// the admin distrusts the claim later: a signed field changes, the approval is gone
	e.adminCall("PATCH", "/api/v1/admin/nodes/"+st.NodeID, `{"hardware_bound":false}`, http.StatusOK, nil)
	if nv := view(st.NodeID); nv.Status != "confirmed" || nv.HardwareBound || !nv.HardwareClaimed {
		t.Fatalf("after patch: %+v", nv)
	}

	// a software-key node cannot be granted hardware_bound, at confirm or later
	soft := e.device("laptop")
	st2 := e.enroll(soft, `{"name":"laptop","platform":"darwin","key_kind":"softkey","roles":["endpoint"]}`)
	e.adminCall("POST", "/api/v1/admin/nodes/"+st2.NodeID+"/confirm", `{"roles":["endpoint"],"hardware_bound":true}`, http.StatusConflict, nil)
	nv2 := e.approve(st2.NodeID, `{"roles":["endpoint"]}`)
	if nv2.HardwareBound {
		t.Fatalf("software key: %+v", nv2)
	}
	e.adminCall("PATCH", "/api/v1/admin/nodes/"+st2.NodeID, `{"hardware_bound":true}`, http.StatusConflict, nil)

	// confirming a TPM node as not hardware-bound is possible from the start
	tpm2 := e.device("vm")
	st3 := e.enroll(tpm2, `{"name":"vm","platform":"linux","key_kind":"tpm2","hardware_bound":true,"roles":["endpoint"]}`)
	if nv3 := e.approve(st3.NodeID, `{"roles":["endpoint"],"hardware_bound":false}`); nv3.HardwareBound {
		t.Fatalf("distrusted at confirm: %+v", nv3)
	}
}

// Changing the overlay pool with nodes in it: refused with the list of nodes
// outside, unless "renumber" is asked for. Then every node keeps its host
// number, approved nodes lose their signature (the address is signed) and
// come back with the new address once the administrator signed again.
func TestRenumberPool(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	hub, laptop := e.device("hub1"), e.device("laptop")
	hst, lst := e.enroll(hub, `{}`), e.enroll(laptop, `{}`)
	hv := e.approve(hst.NodeID, `{"kind":"workload","roles":["hub"]}`)
	lv := e.approve(lst.NodeID, `{"roles":["endpoint"],"overlay_ip":"10.21.3.7"}`)
	if hv.OverlayIP != "10.21.0.1" || lv.OverlayIP != "10.21.3.7" {
		t.Fatalf("addresses before: %s %s", hv.OverlayIP, lv.OverlayIP)
	}

	var refusal struct {
		Error   string           `json:"error"`
		Outside []map[string]any `json:"outside"`
	}
	e.adminCall("PUT", "/api/v1/admin/settings/network", `{"pool":"10.25.0.0/16"}`, http.StatusConflict, &refusal)
	if len(refusal.Outside) != 2 || !strings.Contains(refusal.Error, "renumber") {
		t.Fatalf("refusal: %+v", refusal)
	}
	// a pool too small for a host number changes nothing
	e.adminCall("PUT", "/api/v1/admin/settings/network", `{"pool":"10.25.0.0/24","renumber":true}`, http.StatusConflict, nil)
	var nv api.NodeView
	e.adminCall("GET", "/api/v1/admin/nodes/"+lst.NodeID, "", http.StatusOK, &nv)
	if nv.OverlayIP != "10.21.3.7" || nv.Status != "approved" {
		t.Fatalf("a refused renumbering changed the node: %+v", nv)
	}

	var done struct {
		Renumbered []struct {
			Name     string `json:"name"`
			From, To string
			Unsigned bool `json:"needs_signature"`
		} `json:"renumbered"`
	}
	e.adminCall("PUT", "/api/v1/admin/settings/network", `{"pool":"10.25.0.0/16","renumber":true}`, http.StatusOK, &done)
	if len(done.Renumbered) != 2 || !done.Renumbered[0].Unsigned {
		t.Fatalf("renumbered: %+v", done)
	}
	e.adminCall("GET", "/api/v1/admin/nodes/"+lst.NodeID, "", http.StatusOK, &nv)
	if nv.OverlayIP != "10.25.3.7" || nv.Status != "confirmed" {
		t.Fatalf("laptop after renumbering: %s %s", nv.OverlayIP, nv.Status)
	}
	// without a signature over the new address the node is served nothing
	if code, _ := e.snapshot(laptop, 0, "1s"); code == http.StatusOK {
		t.Fatal("a renumbered node was served a snapshot before it was signed again")
	}
	e.approve(hst.NodeID, `{"kind":"workload","roles":["hub"]}`)
	lv = e.approve(lst.NodeID, `{"roles":["endpoint"]}`)
	if lv.OverlayIP != "10.25.3.7" || lv.Status != "approved" {
		t.Fatalf("laptop signed again: %+v", lv)
	}
	_, snap := e.snapshot(laptop, 0, "1s")
	if snap == nil || snap.Self.OverlayIP.String() != "10.25.3.7" || snap.Pool.String() != "10.25.0.0/16" || len(snap.Peers) != 1 || snap.Peers[0].OverlayIP.String() != "10.25.0.1" {
		t.Fatalf("snapshot after renumbering: %+v", snap)
	}
}
