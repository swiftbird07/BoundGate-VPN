package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

func adminKey(t *testing.T) ssh.Signer {
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

func TestTrustStoreFollowsOnlySignedChanges(t *testing.T) {
	dir := t.TempDir()
	a, b, evil := adminKey(t), adminKey(t), adminKey(t)
	v1 := extend(t, nil, a, a)
	v2 := extend(t, v1, a, a, b)
	v3 := extend(t, v2, b, b) // A removed

	ts, err := loadTrust(dir, "")
	if err != nil || ts.current().Pinned() {
		t.Fatalf("fresh store: %+v %v", ts.current(), err)
	}
	if moved, first, err := ts.apply(v1); err != nil || !moved || !first {
		t.Fatalf("first pin: %v %v %v", moved, first, err)
	}
	if moved, first, err := ts.apply(v3); err != nil || !moved || first || ts.current().Version != 3 {
		t.Fatalf("follow to v3: %v %v %v %+v", moved, first, err, ts.current())
	}
	if ts.signers().Contains(a.PublicKey()) || !ts.signers().Contains(b.PublicKey()) {
		t.Fatalf("signers after v3: %v", ts.signers().Fingerprints())
	}

	// a restart keeps the version: the old list is not accepted again
	ts2, err := loadTrust(dir, "")
	if err != nil || ts2.current().Version != 3 || ts2.current().Hash != ts.current().Hash {
		t.Fatalf("reload: %+v %v", ts2.current(), err)
	}
	for name, chain := range map[string][]binding.SignedSet{
		"rollback to v2":         v2,
		"rollback to v1":         v1,
		"removed key extends":    extend(t, v3[:2], a, a, evil),
		"invented chain":         extend(t, extend(t, extend(t, nil, evil, evil), evil, evil), evil, evil),
		"stranger extends v3":    append(slices.Clone(v3), extend(t, v3, evil, evil)[3]),
		"removed key extends v3": append(slices.Clone(v3), extend(t, v3, a, a, b)[3]),
	} {
		if moved, _, err := ts2.apply(chain); err == nil || moved {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
		if ts2.current().Version != 3 || !ts2.signers().Contains(b.PublicKey()) || ts2.signers().Contains(evil.PublicKey()) || ts2.signers().Contains(a.PublicKey()) {
			t.Fatalf("%s: trust changed: %+v", name, ts2.current())
		}
		// and nothing of it reached the disk
		if ts3, err := loadTrust(dir, ""); err != nil || ts3.current().Hash != ts.current().Hash {
			t.Fatalf("%s: disk changed: %v", name, err)
		}
	}
	// the legitimate next step still works afterwards
	v4 := extend(t, v3, b, b, a)
	if moved, _, err := ts2.apply(v4); err != nil || !moved || ts2.current().Version != 4 {
		t.Fatalf("v4: %v %v", moved, err)
	}
}

func TestTrustStoreNeverPinsTwice(t *testing.T) {
	a, evil := adminKey(t), adminKey(t)
	real := extend(t, nil, a, a)
	fake := extend(t, nil, evil, evil)

	t.Run("damaged file is an error, not a fresh start", func(t *testing.T) {
		for name, content := range map[string]string{
			"garbage":    "not json",
			"empty":      "",
			"no keys":    `{"version":3,"hash":"` + strings.Repeat("ab", 32) + `","keys":[]}`,
			"bad key":    `{"version":3,"hash":"` + strings.Repeat("ab", 32) + `","keys":["ssh-ed25519 AAAA"]}`,
			"no version": `{"version":0,"hash":"` + strings.Repeat("ab", 32) + `","keys":["` + binding.KeyString(a.PublicKey()) + `"]}`,
			"no hash":    `{"version":1,"hash":"","keys":["` + binding.KeyString(a.PublicKey()) + `"]}`,
		} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "admin_trust.json"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if ts, err := loadTrust(dir, ""); err == nil {
				t.Fatalf("%s: loaded %+v", name, ts.current())
			}
		}
	})
	t.Run("keys pinned before signed lists are not silently replaced", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "admin_keys"), []byte(binding.KeyString(a.PublicKey())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTrust(dir, ""); err == nil || !strings.Contains(err.Error(), "admin_keys") {
			t.Fatalf("legacy pin: %v", err)
		}
	})
	t.Run("a list that cannot be stored is not adopted", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		dir := t.TempDir()
		ts, _ := loadTrust(dir, "")
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0o700)
		if moved, _, err := ts.apply(real); err == nil || moved || ts.current().Pinned() {
			t.Fatalf("adopted without storing: %v %+v", err, ts.current())
		}
	})
	t.Run("provisioned genesis refuses another first list", func(t *testing.T) {
		dir := t.TempDir()
		ts, _ := loadTrust(dir, binding.HashSet([]byte(real[0].Set)))
		if _, _, err := ts.apply(fake); !errors.Is(err, binding.ErrSetFork) || ts.current().Pinned() {
			t.Fatalf("invented first list with a provisioned genesis: %v", err)
		}
		if moved, first, err := ts.apply(real); err != nil || !moved || !first {
			t.Fatalf("real first list: %v", err)
		}
	})
	t.Run("without provisioning the first list is pinned, the second refused", func(t *testing.T) {
		dir := t.TempDir()
		ts, _ := loadTrust(dir, "")
		if _, _, err := ts.apply(real); err != nil {
			t.Fatal(err)
		}
		if moved, _, err := ts.apply(fake); err == nil || moved || ts.signers().Contains(evil.PublicKey()) {
			t.Fatalf("second first list accepted: %v", err)
		}
	})
	t.Run("state file is private", func(t *testing.T) {
		dir := t.TempDir()
		ts, _ := loadTrust(dir, "")
		if _, _, err := ts.apply(real); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(filepath.Join(dir, "admin_trust.json"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode: %v %v", fi.Mode(), err)
		}
		left, _ := filepath.Glob(filepath.Join(dir, ".admin_trust-*"))
		if len(left) != 0 {
			t.Fatalf("temp files left: %v", left)
		}
	})
}
