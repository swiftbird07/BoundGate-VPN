package binding

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// chainBuilder plays the honest administrators: it extends a chain with
// correctly formed, correctly signed sets.
type chainBuilder struct {
	t     *testing.T
	chain []SignedSet
	trust Trust
}

func pubs(ss ...ssh.Signer) Signers {
	var out Signers
	for _, s := range ss {
		out = append(out, s.PublicKey())
	}
	return out
}

// link builds a signed set that follows prev with the given keys, signed by
// by in namespace ns. It does not care whether that is legitimate.
func link(t *testing.T, prev *Trust, keys Signers, by ssh.Signer, ns string) (SignedSet, Trust) {
	t.Helper()
	set, err := NewSignerSet(prev, keys)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := set.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(by, ns, raw)
	if err != nil {
		t.Fatal(err)
	}
	return SignedSet{Set: string(raw), Signature: sig}, Trust{Version: set.Version, Hash: HashSet(raw), Keys: set.Keys}
}

func (b *chainBuilder) add(by ssh.Signer, keys ...ssh.Signer) *chainBuilder {
	b.t.Helper()
	var prev *Trust
	if b.trust.Pinned() {
		prev = &b.trust
	}
	l, tr := link(b.t, prev, pubs(keys...), by, SignersNamespace)
	b.chain, b.trust = append(b.chain, l), tr
	return b
}

func mustVerify(t *testing.T, cur Trust, chain []SignedSet) Trust {
	t.Helper()
	got, err := VerifyChain(cur, chain, "")
	if err != nil {
		t.Fatalf("honest chain refused: %v", err)
	}
	return got
}

// mustRefuse asserts the error and, above all, that trust did not move.
func mustRefuse(t *testing.T, cur Trust, chain []SignedSet, want error) {
	t.Helper()
	got, err := VerifyChain(cur, chain, "")
	if err == nil {
		t.Fatalf("accepted; trust moved from v%d to v%d with keys %v", cur.Version, got.Version, got.Keys)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("refused with %v, want %v", err, want)
	}
	if got.Version != cur.Version || got.Hash != cur.Hash || !slices.Equal(got.Keys, cur.Keys) {
		t.Fatalf("refused (%v) but trust changed: %+v -> %+v", err, cur, got)
	}
}

func has(tr Trust, s ssh.Signer) bool { return slices.Contains(tr.Keys, KeyString(s.PublicKey())) }

func TestSignerChainHonestLifecycle(t *testing.T) {
	a, b, c := newSigner(t, "ed25519"), newSigner(t, "ecdsa"), newSigner(t, "ed25519")
	cb := &chainBuilder{t: t}
	cb.add(a, a) // genesis {A}, self-signed
	pin := mustVerify(t, Trust{}, cb.chain)
	if pin.Version != 1 || !has(pin, a) {
		t.Fatalf("genesis: %+v", pin)
	}
	cb.add(a, a, b) // A adds B
	pin = mustVerify(t, pin, cb.chain)
	if pin.Version != 2 || !has(pin, a) || !has(pin, b) {
		t.Fatalf("after add: %+v", pin)
	}
	cb.add(b, b, c) // B removes A and adds C in one step
	cb.add(c, c)    // C removes B
	pin = mustVerify(t, pin, cb.chain)
	if pin.Version != 4 || has(pin, a) || has(pin, b) || !has(pin, c) {
		t.Fatalf("after rotation: %+v", pin)
	}
	// the same chain again, and only its tail, change nothing
	if again := mustVerify(t, pin, cb.chain); again.Hash != pin.Hash {
		t.Fatal("re-delivery changed trust")
	}
	if again := mustVerify(t, pin, cb.chain[3:]); again.Hash != pin.Hash {
		t.Fatal("tail delivery changed trust")
	}
	// a node that was offline since version 2 catches up over several links
	behind := mustVerify(t, Trust{}, cb.chain[:2])
	if caught := mustVerify(t, behind, cb.chain); caught.Hash != pin.Hash {
		t.Fatal("catch-up ended somewhere else")
	}
	// and from a partial chain that starts at its pinned version
	if caught := mustVerify(t, behind, cb.chain[1:]); caught.Hash != pin.Hash {
		t.Fatal("partial catch-up ended somewhere else")
	}
	// a fresh node pins the newest set of a full chain
	if fresh := mustVerify(t, Trust{}, cb.chain); fresh.Hash != pin.Hash {
		t.Fatal("fresh node pinned something else")
	}
	sg, err := pin.Signers()
	if err != nil || len(sg) != 1 || !sg.Contains(c.PublicKey()) {
		t.Fatalf("signers: %v %v", sg, err)
	}
}

// The control plane (or anyone without an admin key) tries to change who
// the administrators are.
func TestSignerChainControlPlaneCannotChangeAdmins(t *testing.T) {
	a, b := newSigner(t, "ed25519"), newSigner(t, "ed25519")
	evil := newSigner(t, "ed25519")
	cb := (&chainBuilder{t: t}).add(a, a).add(a, a, b)
	pin := mustVerify(t, Trust{}, cb.chain)

	t.Run("new set signed by a key that only the new set contains", func(t *testing.T) {
		l, _ := link(t, &pin, pubs(a, b, evil), evil, SignersNamespace)
		mustRefuse(t, pin, append(slices.Clone(cb.chain), l), ErrSetSigner)
	})
	t.Run("new set signed by a complete stranger", func(t *testing.T) {
		l, _ := link(t, &pin, pubs(evil), newSigner(t, "ed25519"), SignersNamespace)
		mustRefuse(t, pin, append(slices.Clone(cb.chain), l), ErrSetSigner)
	})
	t.Run("a whole invented chain from an invented genesis", func(t *testing.T) {
		fake := (&chainBuilder{t: t}).add(evil, evil).add(evil, evil).add(evil, evil)
		mustRefuse(t, pin, fake.chain, ErrSetFork)
	})
	t.Run("invented history before the pinned set buys nothing", func(t *testing.T) {
		// A pinned verifier relies on its pin and on what follows it, never
		// on older links: with the real set at the pinned version the
		// delivery is harmless and trust stays exactly where it was ...
		fake := (&chainBuilder{t: t}).add(evil, evil)
		if got := mustVerify(t, pin, append(slices.Clone(fake.chain), cb.chain[1:]...)); got.Hash != pin.Hash || got.Version != pin.Version {
			t.Fatalf("trust moved: %+v", got)
		}
		// ... and a continuation signed by a key of the invented history is refused.
		l, _ := link(t, &pin, pubs(evil), evil, SignersNamespace)
		mustRefuse(t, pin, append(append(slices.Clone(fake.chain), cb.chain[1:]...), l), ErrSetSigner)
		// A verifier without a pin checks the whole chain and refuses it.
		mustRefuse(t, Trust{}, append(slices.Clone(fake.chain), cb.chain[1:]...), ErrSetSequence)
	})
	t.Run("real chain with an invented link in the middle", func(t *testing.T) {
		g := (&chainBuilder{t: t}).add(a, a)
		l, tr := link(t, &g.trust, pubs(a, evil), evil, SignersNamespace)
		l3, _ := link(t, &tr, pubs(evil), evil, SignersNamespace)
		mustRefuse(t, mustVerify(t, Trust{}, g.chain), append(g.chain, l, l3), ErrSetSigner)
	})
	t.Run("signature of a real set moved onto other keys", func(t *testing.T) {
		real := cb.chain[1]
		set, _ := ParseSignerSet([]byte(real.Set))
		set.Keys = append(set.Keys, KeyString(evil.PublicKey()))
		slices.Sort(set.Keys)
		raw, err := set.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		v1 := mustVerify(t, Trust{}, cb.chain[:1])
		mustRefuse(t, v1, []SignedSet{cb.chain[0], {Set: string(raw), Signature: real.Signature}}, ErrSetSignature)
	})
	t.Run("set bytes changed after signing", func(t *testing.T) {
		for i := range len(cb.chain[1].Set) {
			mutated := []byte(cb.chain[1].Set)
			mutated[i] ^= 0x01
			v1 := mustVerify(t, Trust{}, cb.chain[:1])
			mustRefuse(t, v1, []SignedSet{cb.chain[0], {Set: string(mutated), Signature: cb.chain[1].Signature}}, nil)
		}
	})
	t.Run("signature bytes changed", func(t *testing.T) {
		sig := cb.chain[1].Signature
		mid := len(sig) / 2
		c := byte('A')
		if sig[mid] == 'A' {
			c = 'B'
		}
		bad := sig[:mid] + string(c) + sig[mid+1:]
		v1 := mustVerify(t, Trust{}, cb.chain[:1])
		mustRefuse(t, v1, []SignedSet{cb.chain[0], {Set: cb.chain[1].Set, Signature: bad}}, nil)
	})
	t.Run("no signature", func(t *testing.T) {
		v1 := mustVerify(t, Trust{}, cb.chain[:1])
		mustRefuse(t, v1, []SignedSet{cb.chain[0], {Set: cb.chain[1].Set}}, ErrSetSignature)
	})
	// after all of that the honest chain still works
	if got := mustVerify(t, pin, cb.chain); got.Hash != pin.Hash {
		t.Fatal("trust moved")
	}
}

// A removed key (lost, stolen, a departed admin) must be worth nothing to
// nodes that saw the removal, even together with the control plane.
func TestSignerChainRemovedKeyIsPowerless(t *testing.T) {
	a, b := newSigner(t, "ed25519"), newSigner(t, "ed25519")
	evil := newSigner(t, "ed25519")
	cb := (&chainBuilder{t: t}).add(a, a).add(a, a, b).add(b, b) // v3: A removed
	pin := mustVerify(t, Trust{}, cb.chain)
	if has(pin, a) {
		t.Fatal("A still trusted")
	}
	t.Run("removed key signs the next set", func(t *testing.T) {
		l, _ := link(t, &pin, pubs(a, evil), a, SignersNamespace)
		mustRefuse(t, pin, append(slices.Clone(cb.chain), l), ErrSetSigner)
	})
	t.Run("removed key forks the chain where it was still valid", func(t *testing.T) {
		v2 := mustVerify(t, Trust{}, cb.chain[:2])
		l3, tr3 := link(t, &v2, pubs(a, evil), a, SignersNamespace) // a legitimate-looking v3'
		l4, _ := link(t, &tr3, pubs(evil), evil, SignersNamespace)
		fork := append(slices.Clone(cb.chain[:2]), l3, l4)
		mustRefuse(t, pin, fork, ErrSetFork) // the node is at the real v3
		// A node that never saw the real v3 cannot tell the two apart: that
		// is the limit of any revocation (docs/SECURITY.md). It must at
		// least never be able to switch branches afterwards.
		lagging := mustVerify(t, v2, fork)
		mustRefuse(t, lagging, cb.chain, ErrSetFork)
	})
	t.Run("bindings signed by the removed key stop verifying", func(t *testing.T) {
		n := node("node-signed-by-a", registry.RoleEndpoint)
		sign(t, &n, a)
		before, _ := mustVerify(t, Trust{}, cb.chain[:2]).Signers()
		if _, err := VerifyNode(n, before); err != nil {
			t.Fatalf("valid while A was an admin: %v", err)
		}
		after, _ := pin.Signers()
		if _, err := VerifyNode(n, after); !errors.Is(err, ErrUnknownSigner) {
			t.Fatalf("after removal: %v", err)
		}
	})
}

func TestSignerChainRollbackAndReplay(t *testing.T) {
	a, b := newSigner(t, "ed25519"), newSigner(t, "ed25519")
	cb := (&chainBuilder{t: t}).add(a, a).add(a, a, b).add(b, b)
	pin := mustVerify(t, Trust{}, cb.chain)

	t.Run("older chain (rollback to a list that still has A)", func(t *testing.T) {
		mustRefuse(t, pin, cb.chain[:2], ErrSetFork)
		mustRefuse(t, pin, cb.chain[:1], ErrSetFork)
	})
	t.Run("old link replayed as the next one", func(t *testing.T) {
		mustRefuse(t, pin, append(slices.Clone(cb.chain), cb.chain[1]), ErrSetSequence)
	})
	t.Run("version gap", func(t *testing.T) {
		v1 := mustVerify(t, Trust{}, cb.chain[:1])
		mustRefuse(t, v1, []SignedSet{cb.chain[0], cb.chain[2]}, ErrSetSequence)
	})
	t.Run("right version, wrong previous hash", func(t *testing.T) {
		other := (&chainBuilder{t: t}).add(b, b).add(b, b).add(b, b)
		l, _ := link(t, &other.trust, pubs(b), b, SignersNamespace) // v4 of another chain, signed by a key the node trusts
		mustRefuse(t, pin, append(slices.Clone(cb.chain), l), ErrSetSequence)
	})
	t.Run("chain of another deployment run by the same admin key", func(t *testing.T) {
		other := (&chainBuilder{t: t}).add(b, b).add(b, b).add(b, b).add(b, b, newSigner(t, "ed25519"))
		mustRefuse(t, pin, other.chain, ErrSetFork)
	})
	t.Run("chain that does not reach the pinned version", func(t *testing.T) {
		mustRefuse(t, pin, cb.chain[:2], ErrSetFork)
	})
	t.Run("chain that starts after the pinned version", func(t *testing.T) {
		l, _ := link(t, &pin, pubs(b), b, SignersNamespace)
		mustRefuse(t, pin, []SignedSet{l}, ErrSetFork)
	})
	t.Run("unpinned verifier, chain without genesis", func(t *testing.T) {
		mustRefuse(t, Trust{}, cb.chain[1:], ErrSetSequence)
	})
	t.Run("valid prefix, garbage after it: nothing is applied", func(t *testing.T) {
		v1 := mustVerify(t, Trust{}, cb.chain[:1])
		mustRefuse(t, v1, []SignedSet{cb.chain[0], cb.chain[1], {Set: "{}", Signature: "x"}}, ErrSetForm)
	})
}

// Signatures made for another purpose must not count.
func TestSignerChainCrossProtocol(t *testing.T) {
	a := newSigner(t, "ed25519")
	evil := newSigner(t, "ed25519")
	cb := (&chainBuilder{t: t}).add(a, a)
	pin := mustVerify(t, Trust{}, cb.chain)

	for _, ns := range []string{Namespace, "file", "git", "", "boundgate-signers "} {
		t.Run("set signed in namespace "+ns, func(t *testing.T) {
			l, _ := link(t, &pin, pubs(a, evil), a, ns)
			mustRefuse(t, pin, append(slices.Clone(cb.chain), l), ErrSetSignature)
		})
	}
	t.Run("a signer-set signature does not verify as a binding", func(t *testing.T) {
		l, _ := link(t, &pin, pubs(a, evil), a, SignersNamespace)
		if _, err := Verify([]byte(l.Set), l.Signature, pubs(a)); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("binding verifier: %v", err)
		}
	})
	t.Run("a binding the admin really signed is not a signer set", func(t *testing.T) {
		n := node("some-node", registry.RoleHub)
		sign(t, &n, a)
		mustRefuse(t, pin, append(slices.Clone(cb.chain), SignedSet{Set: n.Binding, Signature: n.Signature}), ErrSetForm)
	})
	t.Run("a signer set is not a binding", func(t *testing.T) {
		if _, err := Parse([]byte(cb.chain[0].Set)); err == nil {
			t.Fatal("parsed as a binding")
		}
	})
}

func TestSignerSetForm(t *testing.T) {
	a, b := newSigner(t, "ed25519"), newSigner(t, "ed25519")
	ka, kb := KeyString(a.PublicKey()), KeyString(b.PublicKey())
	if ka > kb {
		ka, kb = kb, ka
	}
	h := strings.Repeat("ab", 32)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	var many []string
	for range MaxSigners + 1 {
		many = append(many, KeyString(newSigner(t, "ed25519").PublicKey()))
	}
	slices.Sort(many)

	bad := map[string]SignerSet{
		"wrong type":              {Type: "boundgate-binding", Version: 1, Keys: []string{ka}},
		"no type":                 {Version: 1, Keys: []string{ka}},
		"version 0":               {Type: SignerSetType, Version: 0, Keys: []string{ka}},
		"genesis with prev":       {Type: SignerSetType, Version: 1, Prev: h, Keys: []string{ka}},
		"later set without prev":  {Type: SignerSetType, Version: 2, Keys: []string{ka}},
		"prev not hex":            {Type: SignerSetType, Version: 2, Prev: strings.Repeat("zz", 32), Keys: []string{ka}},
		"prev too short":          {Type: SignerSetType, Version: 2, Prev: "abcd", Keys: []string{ka}},
		"prev upper case":         {Type: SignerSetType, Version: 2, Prev: strings.ToUpper(h), Keys: []string{ka}},
		"empty list":              {Type: SignerSetType, Version: 2, Prev: h, Keys: nil},
		"duplicate key":           {Type: SignerSetType, Version: 1, Keys: []string{ka, ka}},
		"unsorted":                {Type: SignerSetType, Version: 1, Keys: []string{kb, ka}},
		"too many":                {Type: SignerSetType, Version: 1, Keys: many},
		"rsa key":                 {Type: SignerSetType, Version: 1, Keys: []string{KeyString(rsaPub)}},
		"key with comment":        {Type: SignerSetType, Version: 1, Keys: []string{ka + " admin"}},
		"key with wrong type tag": {Type: SignerSetType, Version: 1, Keys: []string{"ssh-rsa " + strings.SplitN(ka, " ", 2)[1]}},
		"key not base64":          {Type: SignerSetType, Version: 1, Keys: []string{"ssh-ed25519 ????"}},
		"key base64 of garbage":   {Type: SignerSetType, Version: 1, Keys: []string{"ssh-ed25519 AAAA"}},
	}
	for name, s := range bad {
		t.Run(name, func(t *testing.T) {
			if err := s.Validate(); !errors.Is(err, ErrSetForm) {
				t.Fatalf("Validate: %v", err)
			}
			if _, err := s.Canonical(); err == nil {
				t.Fatal("Canonical produced bytes for an invalid set")
			}
			raw, _ := json.Marshal(s)
			if _, err := ParseSignerSet(raw); err == nil {
				t.Fatal("parsed")
			}
		})
	}

	good := SignerSet{Type: SignerSetType, Version: 2, Prev: h, Keys: []string{ka, kb}}
	raw, err := good.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unknown field":    strings.Replace(string(raw), `{"type"`, `{"extra":1,"type"`, 1),
		"reordered":        `{"version":2,"type":"` + SignerSetType + `","prev":"` + h + `","keys":["` + ka + `","` + kb + `"]}`,
		"whitespace":       strings.Replace(string(raw), `,"version"`, `, "version"`, 1),
		"trailing data":    string(raw) + `{}`,
		"trailing newline": string(raw) + "\n",
		"duplicate field":  strings.Replace(string(raw), `"version":2`, `"version":9,"version":2`, 1),
		"array":            `[` + string(raw) + `]`,
		"empty":            ``,
	} {
		t.Run("non-canonical: "+name, func(t *testing.T) {
			if _, err := ParseSignerSet([]byte(doc)); err == nil {
				t.Fatal("parsed")
			}
		})
	}
	if _, err := ParseSignerSet(raw); err != nil {
		t.Fatal(err)
	}
	// two admins building the same decision get the same bytes
	s1, _ := NewSignerSet(nil, pubs(a, b))
	s2, _ := NewSignerSet(nil, pubs(b, a, b))
	r1, _ := s1.Canonical()
	r2, _ := s2.Canonical()
	if string(r1) != string(r2) {
		t.Fatalf("not canonical:\n%s\n%s", r1, r2)
	}
}

func TestSignerChainGenesis(t *testing.T) {
	a, evil := newSigner(t, "ed25519"), newSigner(t, "ed25519")
	t.Run("genesis must be signed by one of its own keys", func(t *testing.T) {
		l, _ := link(t, nil, pubs(a), evil, SignersNamespace)
		mustRefuse(t, Trust{}, []SignedSet{l}, ErrSetSigner)
	})
	t.Run("provisioned genesis hash", func(t *testing.T) {
		real := (&chainBuilder{t: t}).add(a, a).add(a, a, newSigner(t, "ed25519"))
		fake := (&chainBuilder{t: t}).add(evil, evil)
		pin := HashSet([]byte(real.chain[0].Set))
		if _, err := VerifyChain(Trust{}, fake.chain, pin); !errors.Is(err, ErrSetFork) {
			t.Fatalf("invented genesis with a provisioned hash: %v", err)
		}
		got, err := VerifyChain(Trust{}, real.chain, pin)
		if err != nil || got.Version != 2 {
			t.Fatalf("real chain: %+v %v", got, err)
		}
	})
	t.Run("oversized chain", func(t *testing.T) {
		l, _ := link(t, nil, pubs(a), a, SignersNamespace)
		mustRefuse(t, Trust{}, slices.Repeat([]SignedSet{l}, MaxChain+1), ErrSetForm)
	})
	t.Run("all admin key types can sign a set", func(t *testing.T) {
		for _, kind := range []string{"ed25519", "ecdsa"} {
			k := newSigner(t, kind)
			cb := (&chainBuilder{t: t}).add(k, k).add(k, k, a)
			if got := mustVerify(t, Trust{}, cb.chain); got.Version != 2 {
				t.Fatalf("%s: %+v", kind, got)
			}
		}
		k := newSigner(t, "ecdsa384")
		if _, err := NewSignerSet(nil, pubs(k)); !errors.Is(err, ErrSetForm) {
			t.Fatalf("P-384 accepted: %v", err)
		}
	})
}

// No input may move trust without a valid signature, and none may panic.
func FuzzVerifyChain(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := ssh.NewSignerFromKey(priv)
	set, _ := NewSignerSet(nil, Signers{a.PublicKey()})
	raw, _ := set.Canonical()
	sig, _ := Sign(a, SignersNamespace, raw)
	pinned := Trust{Version: 1, Hash: HashSet(raw), Keys: set.Keys}
	next, _ := NewSignerSet(&pinned, Signers{a.PublicKey()})
	nraw, _ := next.Canonical()
	nsig, _ := Sign(a, SignersNamespace, nraw)
	f.Add(string(raw), sig, string(nraw), nsig)
	f.Add(string(raw), sig, "{}", "")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, set1, sig1, set2, sig2 string) {
		chain := []SignedSet{{Set: set1, Signature: sig1}, {Set: set2, Signature: sig2}}
		got, err := VerifyChain(pinned, chain, "")
		if err != nil {
			if got.Hash != pinned.Hash || got.Version != pinned.Version {
				t.Fatalf("error %v but trust moved to %+v", err, got)
			}
			return
		}
		// Accepted: then it is the pinned set, optionally followed by a set
		// that the pinned key really signed.
		if set1 != string(raw) {
			t.Fatalf("accepted a different set at the pinned version: %q", set1)
		}
		if got.Version == 2 {
			s, perr := ParseSSHSIG(sig2)
			if perr != nil || s.Namespace != SignersNamespace || s.Verify([]byte(set2)) != nil || KeyString(s.PublicKey) != set.Keys[0] {
				t.Fatalf("moved to version 2 without a valid signature of the pinned key")
			}
		}
	})
}
