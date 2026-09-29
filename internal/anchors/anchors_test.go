package anchors

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/safefile"
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

// extend appends a list with the given keys, signed by by.
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

func key(b byte) devicekey.SPKIHash {
	var h devicekey.SPKIHash
	h[0], h[31] = b, 0xcd
	return h
}

func signedBinding(t *testing.T, by ssh.Signer, id, deployment string, issued int64) Evidence {
	t.Helper()
	b := binding.Binding{NodeID: id, SPKI: key(1), KeyVersion: 1, Kind: registry.KindInteractive,
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
	return Evidence{Binding: string(raw), Signature: sig}
}

func signedRevocation(t *testing.T, by ssh.Signer, id, deployment string, issued int64) Evidence {
	t.Helper()
	r := binding.Revocation{Type: binding.RevocationType, NodeID: id, SPKI: key(1), Deployment: deployment, Issued: issued}
	raw, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := binding.SignRevocation(by, raw)
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{Revocation: string(raw), Signature: sig}
}

func open(t *testing.T, o Options) *Files {
	t.Helper()
	if o.Owner == 0 {
		o.Owner = -1
	}
	f, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestThePinIsSetOnce(t *testing.T) {
	dir := t.TempDir()
	f := open(t, Options{Dir: dir})
	if _, ok, err := f.Pin(); ok || err != nil {
		t.Fatalf("a pin in an empty directory: %v %v", ok, err)
	}
	if err := f.SetPin(key(1)); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPin(key(1)); err != nil {
		t.Fatalf("the same pin again: %v", err)
	}
	if err := f.SetPin(key(2)); !errors.Is(err, ErrPinned) {
		t.Fatalf("a second pin: %v", err)
	}
	// also for another process that starts later
	g := open(t, Options{Dir: dir})
	if h, ok, err := g.Pin(); !ok || err != nil || h != key(1) {
		t.Fatalf("%v %v %v", h, ok, err)
	}
	if err := g.SetPin(key(2)); !errors.Is(err, ErrPinned) {
		t.Fatalf("a second pin after a restart: %v", err)
	}

	// a pin that is damaged is an error, and no reason to pin again
	if err := os.WriteFile(filepath.Join(dir, PinFile), []byte("not a hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := f.Pin(); ok || err == nil {
		t.Fatal("a damaged pin was read")
	}
	if err := f.SetPin(key(2)); err == nil || errors.Is(err, ErrPinned) {
		t.Fatalf("pinned over a damaged pin: %v", err)
	}

	// the person who owns the directory removes it: then, and only then
	if err := os.Remove(filepath.Join(dir, PinFile)); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPin(key(2)); err != nil {
		t.Fatal(err)
	}

	p := open(t, Options{Dir: t.TempDir(), Pin: key(7).String()})
	if h, ok, _ := p.Pin(); !ok || h != key(7) {
		t.Fatal("the provisioned pin is not the pin")
	}
	if err := p.SetPin(key(7)); !errors.Is(err, ErrProvisioned) {
		t.Fatalf("pinned next to a provisioned pin: %v", err)
	}
}

func TestTheListMovesOnlyAlongSignedLinks(t *testing.T) {
	dir := t.TempDir()
	a, b, evil := admin(t), admin(t), admin(t)
	v1 := extend(t, nil, a, a)
	v2 := extend(t, v1, a, a, b)
	f := open(t, Options{Dir: dir})

	if tr, err := f.Follow(v1); err != nil || tr.Version != 1 {
		t.Fatalf("first pin: %v %v", tr, err)
	}
	// someone else's list, however well signed by its own keys
	if tr, err := f.Follow(extend(t, nil, evil, evil)); err == nil || tr.Version != 1 {
		t.Fatalf("another network's list was taken: %v %v", tr, err)
	}
	// the next version, signed by a key that is not on the list
	forged := extend(t, v1, a, a, evil)
	forged[1] = extend(t, v1, evil, evil)[1]
	if tr, err := f.Follow(forged); err == nil || tr.Version != 1 {
		t.Fatalf("a link signed by a stranger was taken: %v %v", tr, err)
	}
	if tr, err := f.Follow(v2); err != nil || tr.Version != 2 || len(tr.Keys) != 2 {
		t.Fatalf("a signed link was refused: %v %v", tr, err)
	}
	// and never back
	if tr, err := f.Follow(v1); err == nil || tr.Version != 2 {
		t.Fatalf("rolled back: %v %v", tr, err)
	}
	g := open(t, Options{Dir: dir})
	if tr, err := g.Trust(); err != nil || tr.Version != 2 {
		t.Fatalf("after a restart: %v %v", tr, err)
	}

	if err := os.WriteFile(filepath.Join(dir, TrustFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Follow(extend(t, nil, evil, evil)); err == nil {
		t.Fatal("pinned again over a damaged list")
	}

	// a provisioned genesis: another first list is refused
	p := open(t, Options{Dir: t.TempDir(), Genesis: binding.HashSet([]byte(v1[0].Set))})
	if _, err := p.Follow(extend(t, nil, evil, evil)); err == nil {
		t.Fatal("a first list that is not the provisioned one was pinned")
	}
	if _, err := p.Follow(v2); err != nil {
		t.Fatal(err)
	}
}

func TestTheHistoryTakesOnlyWhatIsProven(t *testing.T) {
	dir := t.TempDir()
	a, evil := admin(t), admin(t)
	chain := extend(t, nil, a, a)
	f := open(t, Options{Dir: dir})

	if err := f.Record([]Evidence{signedBinding(t, a, "n1", "", 100)}); err == nil {
		t.Fatal("evidence was taken before any admin key is pinned")
	}
	tr, err := f.Follow(chain)
	if err != nil {
		t.Fatal(err)
	}
	dep := tr.Genesis

	entry := func(id string) Entry {
		t.Helper()
		b, err := f.History()
		if err != nil {
			t.Fatal(err)
		}
		return b[id]
	}
	if err := f.Record([]Evidence{signedBinding(t, a, "n1", dep, 100), signedBinding(t, a, "n2", dep, 50)}); err != nil {
		t.Fatal(err)
	}
	if entry("n1").Issued != 100 || entry("n2").Issued != 50 {
		t.Fatalf("%v %v", entry("n1"), entry("n2"))
	}

	for name, ev := range map[string]Evidence{
		"signed by a stranger":       signedBinding(t, evil, "n1", dep, 900),
		"for another network":        signedBinding(t, a, "n1", strings.Repeat("ab", 32), 900),
		"a revocation by a stranger": signedRevocation(t, evil, "n1", dep, 900),
		"a binding as a revocation":  {Revocation: signedBinding(t, a, "n1", dep, 900).Binding, Signature: signedBinding(t, a, "n1", dep, 900).Signature},
		"a revocation as a binding":  {Binding: signedRevocation(t, a, "n1", dep, 900).Revocation, Signature: signedRevocation(t, a, "n1", dep, 900).Signature},
		"both at once":               {Binding: "{}", Revocation: "{}", Signature: "x"},
		"neither":                    {Signature: "x"},
		"no signature":               {Binding: signedBinding(t, a, "n1", dep, 900).Binding},
	} {
		// with a good piece next to it: all or nothing
		if err := f.Record([]Evidence{signedBinding(t, a, "n3", dep, 10), ev}); err == nil {
			t.Errorf("%s: recorded", name)
		}
		if entry("n1").Issued != 100 || entry("n1").Revoked != 0 || entry("n3").Issued != 0 {
			t.Fatalf("%s: the history moved: %v %v", name, entry("n1"), entry("n3"))
		}
	}
	tampered := signedBinding(t, a, "n1", dep, 900)
	tampered.Binding = strings.Replace(tampered.Binding, `"issued":900`, `"issued":901`, 1)
	if err := f.Record([]Evidence{tampered}); err == nil {
		t.Fatal("a binding changed after it was signed was recorded")
	}

	// only ever forward
	if err := f.Record([]Evidence{signedBinding(t, a, "n1", dep, 40)}); err != nil {
		t.Fatal(err)
	}
	if entry("n1").Issued != 100 {
		t.Fatalf("an older binding moved the history back: %v", entry("n1"))
	}
	if err := f.Record([]Evidence{signedRevocation(t, a, "n1", dep, 150)}); err != nil {
		t.Fatal(err)
	}
	if err := f.Record([]Evidence{signedRevocation(t, a, "n1", dep, 120)}); err != nil {
		t.Fatal(err)
	}
	if e := entry("n1"); e.Issued != 100 || e.Revoked != 150 {
		t.Fatalf("%v", e)
	}

	// and kept
	g := open(t, Options{Dir: dir})
	b, err := g.History()
	if err != nil || b["n1"] != (Entry{Issued: 100, Revoked: 150}) || b["n2"].Issued != 50 {
		t.Fatalf("after a restart: %v %v", b, err)
	}
	if b.Check(binding.Binding{NodeID: "n1", Issued: 140}) != binding.ErrRevoked || b.Check(binding.Binding{NodeID: "n2", Issued: 49}) != binding.ErrRolledBack {
		t.Fatal("the book does not refuse what it should")
	}
	if len(make([]Evidence, MaxEvidence+1)) > MaxEvidence {
		if err := f.Record(make([]Evidence, MaxEvidence+1)); err == nil {
			t.Fatal("more evidence than one record takes")
		}
	}
}

// The worker's view: it reads its parent's files, as its parent's, and
// changes nothing.
func TestAReadersView(t *testing.T) {
	dir := t.TempDir()
	a := admin(t)
	w := open(t, Options{Dir: dir, Shared: true})
	if err := w.SetPin(key(1)); err != nil {
		t.Fatal(err)
	}
	tr, err := w.Follow(extend(t, nil, a, a))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Record([]Evidence{signedBinding(t, a, "n1", tr.Genesis, 100)}); err != nil {
		t.Fatal(err)
	}
	for _, n := range Names {
		if fi, err := os.Stat(filepath.Join(dir, n)); err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s: %v %v", n, fi, err)
		}
	}

	r := open(t, Options{Dir: dir, Owner: os.Geteuid(), ReadOnly: true})
	if h, ok, err := r.Pin(); !ok || err != nil || h != key(1) {
		t.Fatalf("%v %v %v", h, ok, err)
	}
	if got, err := r.Trust(); err != nil || got.Hash != tr.Hash {
		t.Fatalf("%v %v", got, err)
	}
	if b, err := r.History(); err != nil || b["n1"].Issued != 100 {
		t.Fatalf("%v %v", b, err)
	}
	if err := r.SetPin(key(1)); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("a reader pinned: %v", err)
	}
	if _, err := r.Follow(extend(t, extend(t, nil, a, a), a, a, a)); err == nil {
		t.Fatal("a reader moved the list")
	}
	if err := r.Record([]Evidence{signedBinding(t, a, "n1", tr.Genesis, 200)}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("a reader recorded: %v", err)
	}
	// the reader sees what the writer wrote since
	if err := w.Record([]Evidence{signedBinding(t, a, "n1", tr.Genesis, 300)}); err != nil {
		t.Fatal(err)
	}
	if b, err := r.History(); err != nil || b["n1"].Issued != 300 {
		t.Fatalf("%v %v", b, err)
	}

	// files that are someone else's under these names are refused, not read
	stranger := open(t, Options{Dir: dir, Owner: os.Geteuid() + 1, ReadOnly: true})
	if _, _, err := stranger.Pin(); !errors.Is(err, safefile.ErrNotOwn) {
		t.Fatalf("a pin of another user was read: %v", err)
	}
	if _, err := stranger.Trust(); !errors.Is(err, safefile.ErrNotOwn) {
		t.Fatalf("a list of another user was read: %v", err)
	}
	if _, err := stranger.History(); !errors.Is(err, safefile.ErrNotOwn) {
		t.Fatalf("a history of another user was read: %v", err)
	}
	// and a link under the name of one
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, PinFile), filepath.Join(link, PinFile)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := open(t, Options{Dir: link}).Pin(); ok || !errors.Is(err, safefile.ErrNotOwn) {
		t.Fatalf("a link was followed: %v %v", ok, err)
	}
}

// Files from before another user read them are 0600: opened for sharing,
// they become readable.
func TestOlderFilesBecomeReadable(t *testing.T) {
	dir := t.TempDir()
	old := open(t, Options{Dir: dir})
	if err := old.SetPin(key(1)); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, PinFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v", fi.Mode())
	}
	open(t, Options{Dir: dir, Shared: true})
	if fi, _ := os.Stat(filepath.Join(dir, PinFile)); fi.Mode().Perm() != 0o644 {
		t.Fatalf("%v", fi.Mode())
	}
}

func TestTheBookForgetsTheOldestThatIsNoRevocation(t *testing.T) {
	b := Book{}
	b.Revoke("revoked", 1)
	for i := 0; i < MaxHistory-1; i++ {
		b.Saw("n"+string(rune('a'+i%26))+string(rune('0'+i/26%10))+strings.Repeat("x", i/260), int64(i+10))
	}
	if len(b) != MaxHistory {
		t.Fatalf("%d entries", len(b))
	}
	b.Saw("one more", 5)
	if len(b) != MaxHistory || b["revoked"].Revoked != 1 || b["one more"].Issued != 5 {
		t.Fatalf("%d entries, %v %v", len(b), b["revoked"], b["one more"])
	}
}
