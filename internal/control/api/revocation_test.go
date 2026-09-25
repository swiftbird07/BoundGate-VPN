package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
)

// A binding names the network and the time it was issued, and a revoked
// node's revocation is signed like a binding and then travels with every
// snapshot: what lets a node refuse the old binding even if this control
// plane serves it again (R119).
func TestSignedRevocation(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	a, hub := e.device("laptop"), e.device("hub1")
	st := e.enroll(a, `{"name":"laptop","roles":["endpoint"]}`)
	hst := e.enroll(hub, `{"name":"hub1","roles":["hub"],"public_addr":"hub1:443"}`)
	before := time.Now().Add(-time.Minute).Unix()
	e.approve(st.NodeID, `{"fingerprint":"`+a.spki+`","roles":["endpoint"]}`)
	e.approve(hst.NodeID, `{"roles":["hub"],"public_addr":"hub1:443"}`)

	_, hs := e.snapshot(hub, 0, "1s")
	if hs == nil || len(hs.Peers) != 1 {
		t.Fatalf("hub snapshot: %+v", hs)
	}
	tr, err := binding.VerifyChain(binding.Trust{}, hs.SignerChain, "")
	if err != nil || tr.Genesis == "" {
		t.Fatalf("chain: %+v %v", tr, err)
	}
	b, err := binding.Parse([]byte(hs.Peers[0].Binding))
	if err != nil {
		t.Fatal(err)
	}
	if b.Deployment != tr.Genesis || b.Issued < before || b.Issued > time.Now().Unix()+1 {
		t.Fatalf("binding does not name the network and its time: %+v (genesis %s)", b, tr.Genesis)
	}

	// only a revoked node has a revocation to sign
	e.adminCall("POST", "/api/v1/admin/nodes/"+st.NodeID+"/revocation", "", http.StatusConflict, nil)

	e.adminCall("DELETE", "/api/v1/admin/nodes/"+st.NodeID, "", http.StatusNoContent, nil)
	var nv api.NodeView
	e.adminCall("GET", "/api/v1/admin/nodes/"+st.NodeID, "", http.StatusOK, &nv)
	if nv.Status != "revoked" || nv.RevocationSigned {
		t.Fatalf("%+v", nv)
	}
	var cr api.ConfirmResponse
	e.adminCall("POST", "/api/v1/admin/nodes/"+st.NodeID+"/revocation", "", http.StatusOK, &cr)
	if cr.SignToken == "" || cr.SignCommand == "" {
		t.Fatalf("no sign token: %+v", cr)
	}

	code, raw := e.signCall(cr.SignToken, "GET", "/api/v1/sign/binding", "")
	if code != http.StatusOK {
		t.Fatalf("fetch: %d %s", code, raw)
	}
	var sb api.SignBinding
	if err := json.Unmarshal(raw, &sb); err != nil {
		t.Fatal(err)
	}
	if sb.Binding != "" || sb.Revocation == "" || sb.Namespace != binding.RevocationNamespace {
		t.Fatalf("not a revocation to sign: %+v", sb)
	}
	rv, err := binding.ParseRevocation([]byte(sb.Revocation))
	if err != nil || rv.NodeID != st.NodeID || rv.SPKI.String() != a.spki || rv.Deployment != tr.Genesis {
		t.Fatalf("%+v %v", rv, err)
	}

	post := func(sig string) (int, []byte) {
		body, _ := json.Marshal(api.SignatureBody{Signature: sig})
		return e.signCall(cr.SignToken, "POST", "/api/v1/sign/signature", string(body))
	}
	// a signature in the binding namespace is not a revocation
	wrongNS, _ := binding.Sign(e.signer, binding.Namespace, []byte(sb.Revocation))
	if code, b := post(wrongNS); code == http.StatusOK {
		t.Fatalf("binding-namespace signature accepted as revocation: %s", b)
	}
	// nor does a key outside the admin list count
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	stranger, _ := ssh.NewSignerFromKey(strangerPriv)
	strangerSig, _ := binding.SignRevocation(stranger, []byte(sb.Revocation))
	if code, b := post(strangerSig); code != http.StatusForbidden {
		t.Fatalf("stranger revocation: %d %s", code, b)
	}
	sig, err := binding.SignRevocation(e.signer, []byte(sb.Revocation))
	if err != nil {
		t.Fatal(err)
	}
	if code, b := post(sig); code != http.StatusOK {
		t.Fatalf("sign revocation: %d %s", code, b)
	}
	if code, b := post(sig); code != http.StatusConflict {
		t.Fatalf("token reuse: %d %s", code, b)
	}

	e.adminCall("GET", "/api/v1/admin/nodes/"+st.NodeID, "", http.StatusOK, &nv)
	if !nv.RevocationSigned {
		t.Fatalf("%+v", nv)
	}
	// every node receives it and can check it against its own admin keys
	_, hs2 := e.snapshot(hub, hs.Version, "1s")
	if hs2 == nil || hs2.Version <= hs.Version || len(hs2.Revocations) != 1 || len(hs2.Peers) != 0 {
		t.Fatalf("hub snapshot after revocation: %+v", hs2)
	}
	got, err := binding.VerifyRevocation(hs2.Revocations[0], binding.Signers{e.signer.PublicKey()}, nil)
	if err != nil || got.NodeID != st.NodeID {
		t.Fatalf("%+v %v", got, err)
	}
}
