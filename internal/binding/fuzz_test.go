package binding

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Admin keys arrive with the enrollment status and in signer sets from the
// control plane; the node parses them before it trusts anything.
func FuzzParseSigners(f *testing.F) {
	f.Add(vectorPub + "\n# comment\n\n")
	f.Add("sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIE5sJKuHNqfv5c6N2Q5Ib4t4E2g5xk3o2j4h2z0p8W5HAAAABHNzaDo= x\n")
	f.Add("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0 x")
	f.Fuzz(func(t *testing.T, text string) {
		signers, err := ParseSigners([]byte(text))
		if err != nil {
			return
		}
		for _, k := range signers {
			if CheckSignerType(k) != nil {
				t.Fatalf("accepted a %s key", k.Type())
			}
			if !signers.Contains(k) {
				t.Fatal("a parsed key is not contained")
			}
		}
	})
}

// A signer set parses only from its one canonical form.
func FuzzParseSignerSet(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := ssh.NewSignerFromKey(priv)
	set, _ := NewSignerSet(nil, Signers{a.PublicKey()})
	raw, _ := set.Canonical()
	f.Add(string(raw))
	next, _ := NewSignerSet(&Trust{Version: 1, Hash: HashSet(raw), Keys: set.Keys}, Signers{a.PublicKey()})
	nraw, _ := next.Canonical()
	f.Add(string(nraw))
	f.Add("{}")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseSignerSet([]byte(s))
		if err != nil {
			return
		}
		c, err := got.Canonical()
		if err != nil || string(c) != s {
			t.Fatalf("parsed %q but canonical %q (%v)", s, c, err)
		}
		if _, err := (Trust{Version: got.Version, Keys: got.Keys}).Signers(); err != nil {
			t.Fatalf("keys of a valid set do not parse: %v", err)
		}
	})
}
