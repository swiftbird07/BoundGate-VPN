package binding

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// memGuard is the node's history without the disk.
type memGuard struct {
	dep     string
	issued  map[string]int64
	revoked map[string]int64
}

func newMemGuard(dep string) *memGuard {
	return &memGuard{dep: dep, issued: map[string]int64{}, revoked: map[string]int64{}}
}

func (g *memGuard) Deployment() string { return g.dep }
func (g *memGuard) Check(b Binding) error {
	if r := g.revoked[b.NodeID]; r != 0 && b.Issued <= r {
		return ErrRevoked
	}
	if b.Issued < g.issued[b.NodeID] {
		return ErrRolledBack
	}
	return nil
}
func (g *memGuard) Saw(b Binding) {
	if b.Issued > g.issued[b.NodeID] {
		g.issued[b.NodeID] = b.Issued
	}
}
func (g *memGuard) Revoke(r Revocation) {
	if r.Issued > g.revoked[r.NodeID] {
		g.revoked[r.NodeID] = r.Issued
	}
}

var (
	labNet  = strings.Repeat("a", 64)
	prodNet = strings.Repeat("b", 64)
)

func signAt(t *testing.T, n registry.Node, s ssh.Signer, dep string, issued int64) registry.Node {
	t.Helper()
	b := FromNode(n)
	b.Deployment, b.Issued = dep, issued
	raw, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(s, Namespace, raw)
	if err != nil {
		t.Fatal(err)
	}
	n.Binding, n.Signature = string(raw), sig
	return n
}

func revoke(t *testing.T, id string, n registry.Node, s ssh.Signer, dep string, issued int64) registry.SignedRevocation {
	t.Helper()
	raw, err := Revocation{Type: RevocationType, NodeID: id, SPKI: n.SPKI, Deployment: dep, Issued: issued}.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignRevocation(s, raw)
	if err != nil {
		t.Fatal(err)
	}
	return registry.SignedRevocation{Revocation: string(raw), Signature: sig}
}

func guardSnap(self registry.Node, peers ...registry.Node) *registry.Snapshot {
	return &registry.Snapshot{Self: self, Peers: peers, Pool: netip.MustParsePrefix("10.21.0.0/16")}
}

// A control plane can serve any binding it ever stored. With the guard, a
// node takes none that is older than what it saw, none from before a
// revocation, and none signed for another network.
func TestGuardRefusesWhatTheControlPlaneCouldReplay(t *testing.T) {
	admin := newSigner(t, "ed25519")
	signers := pubs(admin)
	g := newMemGuard(prodNet)
	self := signAt(t, node("self", registry.RoleEndpoint), admin, prodNet, 100)

	// a hub is demoted: the new binding is newer
	hubNode := node("hub", registry.RoleHub)
	wasHub := signAt(t, hubNode, admin, prodNet, 100)
	demoted := signAt(t, node("hub", registry.RoleEndpoint), admin, prodNet, 200)
	if rej, err := VerifySnapshot(guardSnap(self, demoted), signers, g); err != nil || len(rej) != 0 {
		t.Fatal(err, rej)
	}
	// the old grant comes back: refused
	snap := guardSnap(self, wasHub)
	if rej, err := VerifySnapshot(snap, signers, g); err != nil || len(rej) != 1 || !errors.Is(rej[0].Err, ErrRolledBack) {
		t.Fatalf("a rolled-back grant: %v %+v", err, rej)
	}

	// a laptop is revoked; its last binding is served again: refused
	laptop := signAt(t, node("laptop", registry.RoleEndpoint), admin, prodNet, 150)
	snap = guardSnap(self, laptop)
	snap.Revocations = []registry.SignedRevocation{revoke(t, "laptop", laptop, admin, prodNet, 300)}
	if rej, err := VerifySnapshot(snap, signers, g); err != nil || len(rej) != 1 || !errors.Is(rej[0].Err, ErrRevoked) {
		t.Fatalf("a revoked node: %v %+v", err, rej)
	}
	// without the revocation in the snapshot it stays revoked
	if rej, _ := VerifySnapshot(guardSnap(self, laptop), signers, g); len(rej) != 1 {
		t.Fatalf("the revocation was forgotten: %+v", rej)
	}
	// an admin who approves it again signs a newer binding
	again := signAt(t, node("laptop", registry.RoleEndpoint), admin, prodNet, 400)
	if rej, err := VerifySnapshot(guardSnap(self, again), signers, g); err != nil || len(rej) != 0 {
		t.Fatalf("re-approved: %v %+v", err, rej)
	}

	// a binding from the lab, signed by the same key
	lab := signAt(t, node("labhub", registry.RoleHub), admin, labNet, 500)
	if rej, _ := VerifySnapshot(guardSnap(self, lab), signers, g); len(rej) != 1 || !errors.Is(rej[0].Err, ErrOtherDeployment) {
		t.Fatalf("a lab binding: %+v", rej)
	}
	// a binding signed before the fields existed still counts, also next to
	// one that names the network (a network is re-signed node by node) ...
	legacy := node("legacy", registry.RoleHub)
	sign(t, &legacy, admin)
	if rej, _ := VerifySnapshot(guardSnap(self, legacy), signers, g); len(rej) != 0 {
		t.Fatalf("a binding without a network in a mixed network: %+v", rej)
	}
	// ... until the node was signed again: then the old one is a rollback
	resigned := signAt(t, node("legacy", registry.RoleHub), admin, prodNet, 700)
	if rej, _ := VerifySnapshot(guardSnap(self, resigned), signers, g); len(rej) != 0 {
		t.Fatalf("re-signed: %+v", rej)
	}
	if rej, _ := VerifySnapshot(guardSnap(self, legacy), signers, g); len(rej) != 1 || !errors.Is(rej[0].Err, ErrRolledBack) {
		t.Fatalf("the unsigned-network binding after a newer one: %+v", rej)
	}
	// the own binding rolled back: the node stops
	oldSelf := signAt(t, node("self", registry.RoleEndpoint), admin, prodNet, 50)
	if _, err := VerifySnapshot(guardSnap(oldSelf), signers, g); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("own rolled-back binding: %v", err)
	}
	// a revocation signed by nobody the node trusts is not applied
	stranger := newSigner(t, "ed25519")
	snap = guardSnap(self, again)
	snap.Revocations = []registry.SignedRevocation{revoke(t, "laptop", again, stranger, prodNet, 900)}
	if rej, err := VerifySnapshot(snap, signers, g); err != nil || len(snap.Peers) != 1 || len(rej) != 1 {
		t.Fatalf("a forged revocation: %v peers %d %+v", err, len(snap.Peers), rej)
	}
}

// Bindings made before the fields existed keep working where the node's
// own binding has none either.
func TestGuardAcceptsOlderBindingsInAnOlderNetwork(t *testing.T) {
	admin := newSigner(t, "ed25519")
	self, peer := node("self", registry.RoleEndpoint), node("peer", registry.RoleHub)
	sign(t, &self, admin)
	sign(t, &peer, admin)
	if rej, err := VerifySnapshot(guardSnap(self, peer), pubs(admin), newMemGuard(prodNet)); err != nil || len(rej) != 0 {
		t.Fatal(err, rej)
	}
}

// A revocation is its own statement: a binding's signature does not read
// as one, and its bytes are canonical.
func TestRevocationNamespaceAndForm(t *testing.T) {
	admin := newSigner(t, "ed25519")
	n := node("laptop", registry.RoleEndpoint)
	sr := revoke(t, "laptop", n, admin, prodNet, 10)
	if _, err := VerifyRevocation(sr, pubs(admin), nil); err != nil {
		t.Fatal(err)
	}
	asBinding, _ := Sign(admin, Namespace, []byte(sr.Revocation))
	if _, err := VerifyRevocation(registry.SignedRevocation{Revocation: sr.Revocation, Signature: asBinding}, pubs(admin), nil); err == nil {
		t.Fatal("a signature in the binding namespace read as a revocation")
	}
	spaced := strings.Replace(sr.Revocation, `","`, `", "`, 1)
	if _, err := ParseRevocation([]byte(spaced)); err == nil {
		t.Fatal("non-canonical bytes accepted")
	}
}

// The network's identity is the genesis hash: learned with the pin, and by
// a node pinned before it was recorded, from the chain's previous-hashes.
func TestTrustLearnsTheGenesis(t *testing.T) {
	a1, a2 := newSigner(t, "ed25519"), newSigner(t, "ed25519")
	b := &chainBuilder{t: t}
	b.add(a1, a1).add(a1, a1, a2).add(a2, a2)
	got := mustVerify(t, Trust{}, b.chain)
	want := HashSet([]byte(b.chain[0].Set))
	if got.Genesis != want {
		t.Fatalf("genesis %q, want %q", got.Genesis, want)
	}
	// pinned at version 2 without a genesis (an older node): learned later
	old := mustVerify(t, Trust{}, b.chain[:2])
	old.Genesis = ""
	if again := mustVerify(t, old, b.chain); again.Genesis != want {
		t.Fatalf("genesis learned later %q, want %q", again.Genesis, want)
	}
}
