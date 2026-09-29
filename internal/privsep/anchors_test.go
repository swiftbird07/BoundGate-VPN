//go:build linux

package privsep

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

func admin(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func extend(t *testing.T, chain []binding.SignedSet, by ssh.Signer, keys ...ssh.Signer) []binding.SignedSet {
	t.Helper()
	var prev *binding.Trust
	if len(chain) > 0 {
		tr, err := binding.VerifyChain(binding.Trust{}, chain, "")
		if err != nil {
			t.Fatal(err)
		}
		prev = &tr
	}
	var pubs binding.Signers
	for _, k := range keys {
		pubs = append(pubs, k.PublicKey())
	}
	set, err := binding.NewSignerSet(prev, pubs)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := set.Canonical()
	sig, err := binding.SignSet(by, raw)
	if err != nil {
		t.Fatal(err)
	}
	return append(slices.Clone(chain), binding.SignedSet{Set: string(raw), Signature: sig})
}

func spki(b byte) devicekey.SPKIHash {
	var h devicekey.SPKIHash
	h[0], h[31] = b, 0xcd
	return h
}

func proof(t *testing.T, by ssh.Signer, id, deployment string, issued int64) anchors.Evidence {
	t.Helper()
	b := binding.Binding{NodeID: id, SPKI: spki(1), KeyVersion: 1, Kind: registry.KindInteractive,
		Roles: []registry.Role{registry.RoleEndpoint}, OverlayIP: netip.MustParseAddr("10.21.0.4"),
		Deployment: deployment, Issued: issued}
	raw, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := binding.Sign(by, binding.Namespace, raw)
	if err != nil {
		t.Fatal(err)
	}
	return anchors.Evidence{Binding: string(raw), Signature: sig}
}

// separated is a parent with its anchors in dir and a worker's view of them.
func separated(t *testing.T, dir string) (anchors.Anchors, *Client) {
	t.Helper()
	files, err := anchors.Open(anchors.Options{Dir: dir, Owner: -1, Shared: true})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &Parent{Key: testKey{priv}, Net: &fakeNet{}, TUNName: "bg0", WorkerUID: 65531, Anchors: files, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := pair(t, p)
	h, _, err := c.Hello(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.ParentUID != os.Geteuid() {
		t.Fatalf("the parent is uid %d, it says %d", os.Geteuid(), h.ParentUID)
	}
	a, err := c.Anchors(dir, h.ParentUID, anchors.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return a, c
}

// What a worker can do to what the node trusts: pin once, follow signed
// links, prove what it saw. A worker that was taken over can do no more,
// and the next worker starts from what the parent kept.
func TestTheParentKeepsWhatTheNodeTrusts(t *testing.T) {
	dir := t.TempDir()
	w, _ := separated(t, dir)
	a, b, evil := admin(t), admin(t), admin(t)

	// the pin: once
	if _, ok, err := w.Pin(); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if err := w.SetPin(spki(1)); err != nil {
		t.Fatal(err)
	}
	if h, ok, err := w.Pin(); !ok || err != nil || h != spki(1) {
		t.Fatalf("the worker does not see the pin: %v %v %v", h, ok, err)
	}
	if err := w.SetPin(spki(2)); err == nil || !strings.Contains(err.Error(), "pinned already") {
		t.Fatalf("the worker pinned another control plane: %v", err)
	}

	// the list: along signed links, however long the chain
	chain := extend(t, nil, a, a)
	tr, err := w.Follow(chain)
	if err != nil || tr.Version != 1 {
		t.Fatalf("%v %v", tr, err)
	}
	if tr, err := w.Follow(extend(t, nil, evil, evil)); err == nil || tr.Version != 1 {
		t.Fatalf("the worker replaced the list: %v %v", tr, err)
	}
	forged := append(slices.Clone(chain), extend(t, chain, evil, evil)[1])
	if tr, err := w.Follow(forged); err == nil || tr.Version != 1 {
		t.Fatalf("the worker moved the list with a stranger's signature: %v %v", tr, err)
	}
	long := chain
	for i := 0; i < 120; i++ { // more than one message holds
		if i%2 == 0 {
			long = extend(t, long, a, a, b)
		} else {
			long = extend(t, long, b, a)
		}
	}
	size := 0
	for _, l := range long {
		size += len(l.Set) + len(l.Signature)
	}
	if size < 2*pieceBytes {
		t.Fatalf("a chain of %d bytes does not test the pieces", size)
	}
	tr, err = w.Follow(long)
	if err != nil || tr.Version != 121 {
		t.Fatalf("a long chain: version %d, %v", tr.Version, err)
	}
	if got, err := w.Trust(); err != nil || got.Hash != tr.Hash {
		t.Fatalf("the worker does not see the list: %v %v", got, err)
	}
	// pieces a worker left behind do not keep the next chain from verifying
	if _, err := w.(*remoteAnchors).c.call(context.Background(), opFollowSigners, followArgs{Links: forged[1:], More: true}, nil); err != nil {
		t.Fatal(err)
	}
	if tr, err := w.Follow(extend(t, long, a, a, b)); err != nil || tr.Version != 122 {
		t.Fatalf("after a chain that was refused: %v %v", tr, err)
	}

	// the history: with proof
	dep := tr.Genesis
	if err := w.Record([]anchors.Evidence{proof(t, a, "n1", dep, 100)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Record([]anchors.Evidence{proof(t, evil, "n1", dep, 1<<40)}); err == nil {
		t.Fatal("the worker moved the history without an admin's signature")
	}
	if book, err := w.History(); err != nil || book["n1"].Issued != 100 {
		t.Fatalf("%v %v", book, err)
	}

	// the next worker
	next, _ := separated(t, dir)
	if h, ok, _ := next.Pin(); !ok || h != spki(1) {
		t.Fatal("the pin did not stay")
	}
	if got, _ := next.Trust(); got.Version != 122 {
		t.Fatalf("the list did not stay: %v", got)
	}
	if err := next.SetPin(spki(3)); err == nil {
		t.Fatal("the next worker pinned another control plane")
	}
}

// panics is an anchor store with a bug.
type panics struct{ anchors.Anchors }

func (panics) Record([]anchors.Evidence) error {
	panic("a bug in what the parent does with the worker's bytes")
}

// The parent is the process that must stay: what it cannot handle is an
// error for the worker, and the next request is answered.
func TestTheParentOutlivesAPanic(t *testing.T) {
	files, err := anchors.Open(anchors.Options{Dir: t.TempDir(), Owner: -1, Shared: true})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := pair(t, &Parent{Key: testKey{priv}, Net: &fakeNet{}, TUNName: "bg0", Anchors: panics{files}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx := context.Background()
	if _, err := c.call(ctx, opRecord, recordArgs{Evidence: []anchors.Evidence{{Binding: "{}", Signature: "x"}}}, nil); err == nil {
		t.Fatal("a panic was an answer")
	}
	if _, _, err := c.Hello(ctx); err != nil {
		t.Fatalf("the parent is gone: %v", err)
	}
	if _, err := c.call(ctx, opPinControl, pinArgs{SPKI: spki(1).String()}, nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []any{pinArgs{SPKI: "zz"}, "text", nil} {
		if _, err := c.call(ctx, opPinControl, bad, nil); err == nil {
			t.Fatalf("%v was pinned", bad)
		}
	}
}
