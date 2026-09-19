package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
)

func newAdminKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// nodeTrust is what a node that follows the control plane would accept now.
func (e *env) nodeTrust(d dev, cur binding.Trust) (binding.Trust, error) {
	e.t.Helper()
	code, snap := e.snapshot(d, 0, "1s")
	if code != http.StatusOK || snap == nil {
		e.t.Fatalf("snapshot: %d", code)
	}
	return binding.VerifyChain(cur, snap.SignerChain, "")
}

func (e *env) propose(body string, want int) api.SignerChangeView {
	e.t.Helper()
	var ch api.SignerChangeView
	e.adminCall("POST", "/api/v1/admin/signers/change", body, want, &ch)
	return ch
}

func fp(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }

// The whole life of the admin key list through the API, with every shortcut
// an attacker with the admin session, the tokens, the database or a removed
// key could try.
func TestSignerListCanOnlyChangeWithAnAdminKey(t *testing.T) {
	e := newEnv(t)
	a, b, stranger := e.signer, newAdminKey(t), newAdminKey(t)

	// --- no list yet: nothing can be enrolled or approved
	probe := e.device("probe")
	if code, _ := e.nodeCall(probe, "POST", "/api/v1/node/enroll", `{"roles":["endpoint"]}`); code != http.StatusServiceUnavailable {
		t.Fatalf("enroll without a signed list: %d", code)
	}

	// --- the first list: registering a key is only a proposal
	first := e.propose(`{"add":[{"name":"alice","public_key":"`+authorizedKey(a)+`"}]}`, http.StatusAccepted)
	if first.Version != 1 || len(first.Keys) != 1 || !slices.Equal(first.Added, []string{fp(a)}) || !strings.Contains(first.SignCommand, "sign-signers") {
		t.Fatalf("%+v", first)
	}
	var list []api.SignerView
	e.adminCall("GET", "/api/v1/admin/signers", "", http.StatusOK, &list)
	if len(list) != 0 {
		t.Fatalf("a proposal already shows up as a signer: %+v", list)
	}
	if code, _ := e.nodeCall(probe, "POST", "/api/v1/node/enroll", `{"roles":["endpoint"]}`); code != http.StatusServiceUnavailable {
		t.Fatalf("an unsigned proposal opened enrollment: %d", code)
	}
	// the first list must be signed by one of its own keys
	if code, body := e.signSigners(first.SignToken, stranger, binding.SignersNamespace); code != http.StatusForbidden {
		t.Fatalf("stranger signed the first list: %d %s", code, body)
	}
	if code, body := e.signSigners(first.SignToken, a, binding.Namespace); code == http.StatusOK {
		t.Fatalf("signature in the binding namespace accepted: %s", body)
	}
	if code, body := e.signSigners(first.SignToken, a, binding.SignersNamespace); code != http.StatusOK {
		t.Fatalf("first list: %d %s", code, body)
	}
	if code, _ := e.signSigners(first.SignToken, a, binding.SignersNamespace); code != http.StatusConflict {
		t.Fatalf("token replay: %d", code)
	}
	if code, _ := e.signCall("bgsigners_"+strings.Repeat("0", 64), "GET", "/api/v1/sign/signers", ""); code != http.StatusUnauthorized {
		t.Fatalf("invented token: %d", code)
	}

	// --- nodes pin the signed list at enrollment
	hub, laptop := e.device("hub"), e.device("laptop")
	hubSt := e.enroll(hub, `{"roles":["hub"],"public_addr":"hub.example:443"}`)
	lapSt := e.enroll(laptop, `{"roles":["endpoint"]}`)
	e.approve(hubSt.NodeID, `{"fingerprint":"`+hub.spki+`","roles":["hub"]}`)
	e.approve(lapSt.NodeID, `{"fingerprint":"`+laptop.spki+`","roles":["endpoint"]}`)
	hubTrust, err := e.nodeTrust(hub, binding.Trust{})
	if err != nil || hubTrust.Version != 1 {
		t.Fatalf("hub pins: %+v %v", hubTrust, err)
	}

	// --- A adds B. Only A can sign that; B cannot vote itself in.
	add := e.propose(`{"add":[{"name":"bob","public_key":"`+authorizedKey(b)+`"}]}`, http.StatusAccepted)
	if add.Version != 2 || !slices.Equal(add.Added, []string{fp(b)}) || len(add.SignableBy) != 1 || !strings.Contains(add.SignableBy[0], fp(a)) {
		t.Fatalf("%+v", add)
	}
	for name, k := range map[string]ssh.Signer{"the key being added": b, "a stranger": stranger} {
		if code, body := e.signSigners(add.SignToken, k, binding.SignersNamespace); code != http.StatusForbidden {
			t.Fatalf("%s signed the change: %d %s", name, code, body)
		}
	}
	// a signature over other bytes (here: over the previous list) does not fit
	{
		var p api.SignSigners
		_, raw := e.signCall(add.SignToken, "GET", "/api/v1/sign/signers", "")
		_ = json.Unmarshal(raw, &p)
		if len(p.Chain) != 1 {
			t.Fatalf("chain for the CLI: %+v", p.Chain)
		}
		body, _ := json.Marshal(api.SignatureBody{Signature: p.Chain[0].Signature})
		if code, rsp := e.signCall(add.SignToken, "POST", "/api/v1/sign/signers", string(body)); code == http.StatusOK {
			t.Fatalf("old signature reused: %s", rsp)
		}
	}
	if tr, _ := e.nodeTrust(hub, hubTrust); tr.Version != 1 {
		t.Fatalf("failed attempts moved the list to %d", tr.Version)
	}
	if code, body := e.signSigners(add.SignToken, a, binding.SignersNamespace); code != http.StatusOK {
		t.Fatalf("A adds B: %d %s", code, body)
	}
	if hubTrust, err = e.nodeTrust(hub, hubTrust); err != nil || hubTrust.Version != 2 || len(hubTrust.Keys) != 2 {
		t.Fatalf("hub follows to v2: %+v %v", hubTrust, err)
	}

	e.handlers.ResetRateLimitsForTest()

	// --- B removes A. Nodes signed by A lose their approval.
	aView := e.signerByKey(a)
	rm := e.propose(`{"remove":["`+aView.ID+`"]}`, http.StatusAccepted)
	if rm.Version != 3 || !slices.Equal(rm.Removed, []string{fp(a)}) || len(rm.AffectedNodes) != 2 {
		t.Fatalf("%+v", rm)
	}
	if code, body := e.signSigners(rm.SignToken, b, binding.SignersNamespace); code != http.StatusOK {
		t.Fatalf("B removes A: %d %s", code, body)
	}
	if code, _ := e.snapshot(hub, 0, "1s"); code != http.StatusForbidden {
		t.Fatalf("a node whose signature no longer counts still gets snapshots: %d", code)
	}
	var nv api.NodeView
	e.adminCall("GET", "/api/v1/admin/nodes/"+hubSt.NodeID, "", http.StatusOK, &nv)
	if nv.Status != "confirmed" {
		t.Fatalf("node signed by the removed key is %s", nv.Status)
	}

	// --- the removed key is worth nothing now
	var cr api.ConfirmResponse
	e.adminCall("POST", "/api/v1/admin/nodes/"+hubSt.NodeID+"/confirm", `{"fingerprint":"`+hub.spki+`","roles":["hub"]}`, http.StatusOK, &cr)
	if code, body := e.signWith(cr.SignToken, a); code != http.StatusForbidden {
		t.Fatalf("removed key approved a node: %d %s", code, body)
	}
	if code, body := e.signWith(cr.SignToken, b); code != http.StatusOK {
		t.Fatalf("B re-signs the hub: %d %s", code, body)
	}
	back := e.propose(`{"add":[{"name":"alice again","public_key":"`+authorizedKey(a)+`"},{"name":"mallory","public_key":"`+authorizedKey(stranger)+`"}]}`, http.StatusAccepted)
	if code, body := e.signSigners(back.SignToken, a, binding.SignersNamespace); code != http.StatusForbidden {
		t.Fatalf("removed key changed the list: %d %s", code, body)
	}
	hubTrust, err = e.nodeTrust(hub, binding.Trust{Version: 2, Hash: hubTrust.Hash, Keys: hubTrust.Keys})
	if err != nil || hubTrust.Version != 3 || !slices.Equal(hubTrust.Keys, []string{authorizedKey(b)}) {
		t.Fatalf("hub at v3: %+v %v", hubTrust, err)
	}

	// --- the list can never become empty
	e.propose(`{"remove":["`+e.signerByKey(b).ID+`"]}`, http.StatusConflict)

	e.handlers.ResetRateLimitsForTest()

	// --- write access to the database buys nothing
	raw, err := sql.Open("sqlite", e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// (1) a key smuggled into the directory is not a signer
	if _, err := raw.Exec(`INSERT INTO admin_signers (id, subject, name, ssh_pubkey, key_type, hardware, fingerprint, created_at) VALUES ('evil', 'root', 'mallory', ?, 'ssh-ed25519', 0, ?, '2026-01-01T00:00:00.000000000Z')`,
		authorizedKey(stranger), fp(stranger)); err != nil {
		t.Fatal(err)
	}
	e.adminCall("GET", "/api/v1/admin/signers", "", http.StatusOK, &list)
	for _, s := range list {
		if s.Fingerprint == fp(stranger) && s.Active {
			t.Fatal("directory row counts as an active signer")
		}
	}
	e.adminCall("POST", "/api/v1/admin/nodes/"+lapSt.NodeID+"/confirm", `{"fingerprint":"`+laptop.spki+`","roles":["endpoint"]}`, http.StatusOK, &cr)
	if code, body := e.signWith(cr.SignToken, stranger); code != http.StatusForbidden {
		t.Fatalf("smuggled key approved a node: %d %s", code, body)
	}
	change := e.propose(`{"add":[{"name":"carol","public_key":"`+authorizedKey(newAdminKey(t))+`"}]}`, http.StatusAccepted)
	if code, body := e.signSigners(change.SignToken, stranger, binding.SignersNamespace); code != http.StatusForbidden {
		t.Fatalf("smuggled key changed the list: %d %s", code, body)
	}
	// (2) a forged link appended to the chain: nodes refuse it and the
	// control plane stops working with the chain instead of serving it as valid
	forged, _ := binding.NewSignerSet(&hubTrust, binding.Signers{b.PublicKey(), stranger.PublicKey()})
	forgedRaw, _ := forged.Canonical()
	forgedSig, _ := binding.SignSet(stranger, forgedRaw)
	if _, err := raw.Exec(`INSERT INTO signer_sets (version, set_json, signature, hash, signed_by, admin, created_at) VALUES (4, ?, ?, ?, ?, 'root', '2026-01-01T00:00:00.000000000Z')`,
		string(forgedRaw), forgedSig, binding.HashSet(forgedRaw), fp(stranger)); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE snapshot_version SET version = version + 1`); err != nil {
		t.Fatal(err)
	}
	if tr, err := e.nodeTrust(hub, hubTrust); err == nil || tr.Version != 3 || slices.Contains(tr.Keys, authorizedKey(stranger)) {
		t.Fatalf("node accepted a forged link: %+v %v", tr, err)
	}
	e.adminCall("GET", "/api/v1/admin/signers", "", http.StatusInternalServerError, nil)
	e.adminCall("POST", "/api/v1/admin/nodes/"+lapSt.NodeID+"/confirm", `{"fingerprint":"`+laptop.spki+`","roles":["endpoint"]}`, http.StatusInternalServerError, nil)
	// (3) rewriting history (rollback to the list that still had A)
	if _, err := raw.Exec(`DELETE FROM signer_sets WHERE version >= 3`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE snapshot_version SET version = version + 1`); err != nil {
		t.Fatal(err)
	}
	if tr, err := e.nodeTrust(hub, hubTrust); err == nil || tr.Version != 3 {
		t.Fatalf("node rolled back: %+v %v", tr, err)
	}
}
