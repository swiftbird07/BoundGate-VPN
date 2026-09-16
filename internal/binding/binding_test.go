package binding

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Test vector produced on macOS with OpenSSH:
//
//	ssh-keygen -t ed25519 -N '' -C test-admin -f id_ed25519
//	printf '%s' '<vectorMessage>' > msg.json
//	ssh-keygen -Y sign -n boundgate-binding -f id_ed25519 msg.json
//	ssh-keygen -Y verify -f allowed -I test-admin -n boundgate-binding -s msg.json.sig < msg.json
//
// The private key is a throwaway generated for this test only.
const (
	vectorMessage = `{"node_id":"n1","spki":"00ff","key_version":1,"kind":"interactive","roles":["endpoint"],"prefixes":[],"overlay_ip":"10.21.0.9"}`
	vectorPub     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJsp33nEg7yhZQf+Y2JVioq0T/EWIJ6d5YhTrpLTDqFw test-admin"
	vectorSig     = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgmynfecSDvKFlB/5jYlWKirRP8R
Ygnp3liFOuktMOoXAAAAARYm91bmRnYXRlLWJpbmRpbmcAAAAAAAAABnNoYTUxMgAAAFMA
AAALc3NoLWVkMjU1MTkAAABA/d3/HSeuXrDdzcxWcCLYdUwD6lBxZ5PVom52fX5UchDEeQ
XFVA2VsJR+fJxfbstUeOrI4CX8sPVz+tZUrNODDg==
-----END SSH SIGNATURE-----
`
	vectorPriv = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCbKd95xIO8oWUH/mNiVYqKtE/xFiCeneWIU66S0w6hcAAAAJBQen95UHp/
eQAAAAtzc2gtZWQyNTUxOQAAACCbKd95xIO8oWUH/mNiVYqKtE/xFiCeneWIU66S0w6hcA
AAAEDOj9TFIRj/ZzvsiIjldSTIb0LWnX/X8Zw50L24C+8qypsp33nEg7yhZQf+Y2JVioq0
T/EWIJ6d5YhTrpLTDqFwAAAACnRlc3QtYWRtaW4BAgM=
-----END OPENSSH PRIVATE KEY-----
`
)

func TestOpenSSHVectorVerifies(t *testing.T) {
	signers, err := ParseSigners([]byte(vectorPub + "\n# comment\n\n"))
	if err != nil || len(signers) != 1 {
		t.Fatal(err, len(signers))
	}
	pub, err := Verify([]byte(vectorMessage), vectorSig, signers)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(pub) != "SHA256:cu/PvyrKd4JLVciZXnf7OkYMRkMhsVVu2spUus2w34Y" {
		t.Fatal(ssh.FingerprintSHA256(pub))
	}
	// one byte of the message changes: refused
	if _, err := Verify([]byte(strings.Replace(vectorMessage, "10.21.0.9", "10.21.0.8", 1)), vectorSig, signers); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered message: %v", err)
	}
	// the signer is not pinned: refused before any crypto
	if _, err := Verify([]byte(vectorMessage), vectorSig, nil); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("unknown signer: %v", err)
	}
	// wrong namespace
	sig, _ := ParseSSHSIG(vectorSig)
	sig.Namespace = "file"
	if _, err := Verify([]byte(vectorMessage), Armor(sig), signers); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("namespace: %v", err)
	}
}

// Ed25519 is deterministic, so signing the vector message with the vector
// key must reproduce ssh-keygen's signature byte for byte. This pins our
// framing to OpenSSH's.
func TestSignMatchesOpenSSH(t *testing.T) {
	signer, err := ssh.ParsePrivateKey([]byte(vectorPriv))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Sign(signer, Namespace, []byte(vectorMessage))
	if err != nil {
		t.Fatal(err)
	}
	if got != vectorSig {
		t.Fatalf("signature differs from ssh-keygen:\n%s\nwant\n%s", got, vectorSig)
	}
}

func TestCanonicalIsStable(t *testing.T) {
	var spki devicekey.SPKIHash
	spki[0], spki[31] = 0xab, 0xcd
	a := Binding{NodeID: "n", SPKI: spki, KeyVersion: 1,
		Roles:    []registry.Role{registry.RoleSubnetRouter, registry.RoleEndpoint, registry.RoleEndpoint},
		Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.178.7/24"), Mode: registry.ModeSNAT}, {Prefix: netip.MustParsePrefix("10.60.0.0/24"), Mode: registry.ModeRouted}},
		OverlayIP: netip.MustParseAddr("10.21.0.4")}
	b := Binding{NodeID: "n", SPKI: spki, KeyVersion: 1,
		Roles:    []registry.Role{registry.RoleEndpoint, registry.RoleSubnetRouter},
		Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("10.60.0.0/24"), Mode: registry.ModeRouted}, {Prefix: netip.MustParsePrefix("192.168.178.0/24"), Mode: registry.ModeSNAT}},
		OverlayIP: netip.MustParseAddr("10.21.0.4")}
	ca, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := b.Canonical()
	if string(ca) != string(cb) {
		t.Fatalf("%s\n%s", ca, cb)
	}
	want := `{"node_id":"n","spki":"ab000000000000000000000000000000000000000000000000000000000000cd","key_version":1,"kind":"interactive","roles":["endpoint","subnet-router"],"prefixes":[{"prefix":"10.60.0.0/24","mode":"routed"},{"prefix":"192.168.178.0/24","mode":"snat"}],"overlay_ip":"10.21.0.4"}`
	if string(ca) != want {
		t.Fatalf("got %s", ca)
	}
	p, err := Parse(ca)
	if err != nil || p.NodeID != "n" || len(p.Prefixes) != 2 {
		t.Fatal(err, p)
	}
	for _, bad := range []string{
		string(ca) + " ",
		strings.Replace(string(ca), `"key_version":1`, `"key_version": 1`, 1),
		strings.Replace(string(ca), `"overlay_ip"`, `"public_addr":"x","overlay_ip"`, 1),
		strings.Replace(string(ca), `["endpoint","subnet-router"]`, `["subnet-router","endpoint"]`, 1),
		strings.Replace(string(ca), `["endpoint","subnet-router"]`, `[]`, 1),
		strings.Replace(string(ca), `"kind":"interactive"`, `"kind":"root"`, 1),
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted non-canonical %s", bad)
		}
	}
	if _, err := (Binding{}).Canonical(); err == nil {
		t.Fatal("empty binding accepted")
	}
}

func newSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var priv any
	switch kind {
	case "ed25519":
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		priv = k
	case "ecdsa":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv = k
	case "ecdsa384":
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		priv = k
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func node(id string, roles ...registry.Role) registry.Node {
	var spki devicekey.SPKIHash
	copy(spki[:], id)
	return registry.Node{ID: transport.DeviceID(id), Name: id, SPKI: spki, KeyVersion: 1, Kind: registry.KindInteractive, Roles: roles, OverlayIP: netip.MustParseAddr("10.21.0.1")}
}

func sign(t *testing.T, n *registry.Node, s ssh.Signer) {
	t.Helper()
	raw, err := FromNode(*n).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(s, Namespace, raw)
	if err != nil {
		t.Fatal(err)
	}
	n.Binding, n.Signature = string(raw), sig
}

func TestVerifyNodeAndSnapshot(t *testing.T) {
	admin1, admin2, stranger := newSigner(t, "ed25519"), newSigner(t, "ecdsa"), newSigner(t, "ed25519")
	signers := Signers{admin1.PublicKey(), admin2.PublicKey()}
	if len(signers.Fingerprints()) != 2 {
		t.Fatal()
	}
	self := node("self", registry.RoleEndpoint)
	sign(t, &self, admin1)
	hub := node("hub", registry.RoleHub)
	hub.PublicAddr = "hub:443"
	sign(t, &hub, admin2)
	unsigned := node("unsigned", registry.RoleEndpoint)
	byStranger := node("stranger", registry.RoleEndpoint)
	sign(t, &byStranger, stranger)
	// signed as endpoint, then the control plane "promotes" it to hub
	promoted := node("promoted", registry.RoleEndpoint)
	sign(t, &promoted, admin1)
	promoted.Roles = []registry.Role{registry.RoleEndpoint, registry.RoleHub}
	// signed binding for another key, copied onto this record
	swapped := node("swapped", registry.RoleEndpoint)
	sign(t, &swapped, admin1)
	swapped.SPKI[5] ^= 1
	// prefix added after signing
	widened := node("widened", registry.RoleSubnetRouter)
	widened.Prefixes = []registry.Prefix{{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Mode: registry.ModeRouted}}
	sign(t, &widened, admin1)
	widened.Prefixes = append(widened.Prefixes, registry.Prefix{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Mode: registry.ModeSNAT})
	// signed as interactive, then the control plane makes it a workload (no login needed)
	rekinded := node("rekinded", registry.RoleEndpoint)
	sign(t, &rekinded, admin1)
	rekinded.Kind = registry.KindWorkload
	// signature copied from another node
	copied := node("copied", registry.RoleEndpoint)
	raw, _ := FromNode(copied).Canonical()
	copied.Binding, copied.Signature = string(raw), hub.Signature

	if _, err := VerifyNode(self, signers); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNode(hub, signers); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []registry.Node{unsigned, byStranger, promoted, swapped, widened, rekinded, copied} {
		if _, err := VerifyNode(bad, signers); err == nil {
			t.Fatalf("%s accepted", bad.ID)
		}
	}

	snap := &registry.Snapshot{Self: self, Peers: []registry.Node{hub, unsigned, byStranger, promoted, swapped, widened, rekinded, copied}, Pool: netip.MustParsePrefix("10.21.0.0/16")}
	rejected, err := VerifySnapshot(snap, signers)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Peers) != 1 || snap.Peers[0].ID != "hub" || len(rejected) != 7 {
		t.Fatalf("peers %+v rejected %+v", snap.Peers, rejected)
	}
	// own binding invalid: the node must not operate
	snap.Self.Roles = append(snap.Self.Roles, registry.RoleHub)
	if _, err := VerifySnapshot(snap, signers); err == nil {
		t.Fatal("tampered self accepted")
	}
	// no pinned keys: nothing verifies
	if _, err := VerifySnapshot(&registry.Snapshot{Self: self}, nil); err == nil {
		t.Fatal("no signers accepted")
	}
}

func TestKeyTypes(t *testing.T) {
	if _, err := Sign(newSigner(t, "ecdsa384"), Namespace, []byte("x")); err == nil {
		t.Fatal("P-384 accepted")
	}
	if _, err := ParseSigners([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0 x")); err == nil {
		t.Fatal("rsa accepted")
	}
	sk := "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIJsp33nEg7yhZQf+Y2JVioq0T/EWIJ6d5YhTrpLTDqFwAAAABHNzaDo= yubikey"
	signers, err := ParseSigners([]byte(sk))
	if err != nil {
		t.Fatal(err)
	}
	if !IsHardwareKey(signers[0]) || IsHardwareKey(newSigner(t, "ed25519").PublicKey()) {
		t.Fatal("hardware detection")
	}
	// a signature by a software key must not verify against the sk key with
	// the same curve point: the types differ
	if _, err := Verify([]byte(vectorMessage), vectorSig, signers); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("sk/ed25519 confusion: %v", err)
	}
}

func FuzzParseSSHSIG(f *testing.F) {
	f.Add(vectorSig)
	f.Add(armorBegin + "\nU1NIU0lH\n" + armorEnd)
	f.Fuzz(func(t *testing.T, s string) {
		sig, err := ParseSSHSIG(s)
		if err != nil {
			return
		}
		_ = sig.Verify([]byte(vectorMessage))
	})
}

func FuzzParseBinding(f *testing.F) {
	f.Add(vectorMessage)
	f.Fuzz(func(t *testing.T, s string) {
		b, err := Parse([]byte(s))
		if err != nil {
			return
		}
		c, err := b.Canonical()
		if err != nil || string(c) != s {
			t.Fatalf("parsed %q but canonical %q (%v)", s, c, err)
		}
	})
}
