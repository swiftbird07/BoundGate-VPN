package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

// A passphrase protected key file is nothing this program can use itself:
// signMessage has to hand it to ssh-keygen, and the signature that comes back
// must verify like one made in process. (A security key takes the same path;
// it needs hardware and is tried by hand.)
func TestSignMessageEncryptedKeyFileViaSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "correct horse", "-C", "test", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	askpass := filepath.Join(dir, "askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho 'correct horse'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOUNDGATE_SSH_KEYGEN", keygen)
	t.Setenv("SSH_ASKPASS", askpass)
	t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	t.Setenv("DISPLAY", ":0")

	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	signers, err := binding.ParseSigners(pub)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"node_id":"n1"}`)
	sig, err := signMessage(key, "", nil, binding.Namespace, msg, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Verify(msg, sig, signers); err != nil {
		t.Fatalf("signature from ssh-keygen does not verify: %v", err)
	}
	// the namespace is part of what is signed
	other, err := signMessage(key, "", nil, binding.SignersNamespace, msg, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Verify(msg, other, signers); err == nil {
		t.Fatal("a signature for another namespace verified as a binding")
	}
	// nothing is left behind next to the key
	left, _ := filepath.Glob(filepath.Join(dir, "*.sig"))
	if len(left) != 0 || strings.Contains(sig, "correct horse") {
		t.Fatalf("leftovers: %v", left)
	}
}
