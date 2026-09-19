// Package sekey is the device key of a macOS node: an ECDSA P-256 key that
// is generated inside the Mac's Secure Enclave and cannot leave it.
//
// The Secure Enclave is only reachable through Apple's frameworks, and the
// node is Go without cgo, so the key operations go through a small Swift
// helper, boundgate-sekey (apps/macos/Sources/boundgate-sekey), one process
// per operation. What the node keeps on disk is the key as wrapped by this
// one Secure Enclave ("blob") and the public key; the blob is useless on any
// other machine. No keychain is involved, so the root daemon can use it.
//
// What this gives and what it does not: the key cannot be copied off the
// machine. It is usable without user presence, because the daemon connects
// unattended - whoever is root on the Mac can ask the Secure Enclave to sign
// while he is on the machine, as with a TPM key without authorization. And
// the control plane has the node's word for it: there is no attestation.
//
// This package is part of the security TCB (docs/TCB.md).
package sekey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// Kind is the key kind in config, status and the registry.
const Kind = "secure-enclave"

// HelperName is the helper's file name; by default it is expected next to
// the node's own executable (the app bundle's Contents/MacOS).
const HelperName = "boundgate-sekey"

const helperTimeout = 15 * time.Second

// blobFile is the key as stored in the state directory.
type blobFile struct {
	Kind   string `json:"kind"`
	Blob   []byte `json:"blob"`   // the key, wrapped by this Mac's Secure Enclave
	Public []byte `json:"public"` // X9.63 uncompressed point
}

// Opener creates the key on first use and loads it afterwards.
type Opener struct {
	Helper string // path of boundgate-sekey; empty: next to this executable
	Path   string // blob file in the state directory
}

// New returns an Opener.
func New(helper, path string) Opener { return Opener{Helper: helper, Path: path} }

// Key is a device key in the Secure Enclave.
type Key struct {
	helper string
	blob   []byte
	pub    *ecdsa.PublicKey
}

var _ devicekey.DeviceKey = (*Key)(nil)

// Open implements devicekey.Opener.
func (o Opener) Open(ctx context.Context) (devicekey.DeviceKey, error) {
	helper, err := findHelper(o.Helper)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(o.Path)
	switch {
	case err == nil:
		var f blobFile
		if err := json.Unmarshal(raw, &f); err != nil || f.Kind != Kind || len(f.Blob) == 0 {
			return nil, fmt.Errorf("sekey: %s is not a Secure Enclave key file", o.Path)
		}
		pub, err := parsePublic(f.Public)
		if err != nil {
			return nil, fmt.Errorf("sekey: %s: %w", o.Path, err)
		}
		// The Secure Enclave must still know this key and it must be the one
		// this node enrolled with. A state directory copied to another Mac
		// fails here.
		out, err := call(ctx, helper, f.Blob, "public")
		if err != nil {
			return nil, fmt.Errorf("sekey: this Mac's Secure Enclave cannot use the key in %s (was the state directory copied from another machine?): %w", o.Path, err)
		}
		if !bytes.Equal(out["public"], f.Public) {
			return nil, fmt.Errorf("sekey: %s: the Secure Enclave reports another public key than the one stored", o.Path)
		}
		return &Key{helper: helper, blob: f.Blob, pub: pub}, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	out, err := call(ctx, helper, nil, "create")
	if err != nil {
		return nil, fmt.Errorf("sekey: create: %w", err)
	}
	pub, err := parsePublic(out["public"])
	if err != nil {
		return nil, fmt.Errorf("sekey: create: %w", err)
	}
	if len(out["blob"]) == 0 {
		return nil, errors.New("sekey: create: the helper returned no key")
	}
	k := &Key{helper: helper, blob: out["blob"], pub: pub}
	// prove the key works before it becomes this node's identity
	probe := make([]byte, crypto.SHA256.Size())
	if _, err := k.Sign(nil, probe, crypto.SHA256); err != nil {
		return nil, fmt.Errorf("sekey: new key does not sign: %w", err)
	}
	if err := writeBlob(o.Path, blobFile{Kind: Kind, Blob: out["blob"], Public: out["public"]}); err != nil {
		return nil, err
	}
	return k, nil
}

// Available reports whether this machine has a Secure Enclave the helper can
// use. False also when the helper is missing (any system but macOS).
func Available(ctx context.Context, helper string) bool {
	path, err := findHelper(helper)
	if err != nil {
		return false
	}
	_, err = call(ctx, path, nil, "available")
	return err == nil
}

// Public implements crypto.Signer.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Sign implements crypto.Signer: ECDSA over a SHA-256 digest, ASN.1 DER.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("sekey: only SHA-256 digests can be signed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	out, err := call(ctx, k.helper, k.blob, "sign", hex.EncodeToString(digest))
	if err != nil {
		return nil, fmt.Errorf("sekey: sign: %w", err)
	}
	sig := out["signature"]
	// The helper is a separate program: take nothing from it on trust.
	if !ecdsa.VerifyASN1(k.pub, digest, sig) {
		return nil, errors.New("sekey: sign: the helper returned a signature that does not verify")
	}
	return sig, nil
}

// HardwareBound implements devicekey.DeviceKey.
func (k *Key) HardwareBound() bool { return true }

// Kind implements devicekey.DeviceKey.
func (k *Key) Kind() string { return Kind }

func parsePublic(x963 []byte) (*ecdsa.PublicKey, error) {
	// rejects anything that is not a point on the curve
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), x963)
	if err != nil {
		return nil, fmt.Errorf("public key is not a P-256 point: %w", err)
	}
	return pub, nil
}

// findHelper resolves the helper and refuses one that others may replace:
// the node runs it as root with the key blob on stdin.
func findHelper(configured string) (string, error) {
	path := configured
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("sekey: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		path = filepath.Join(filepath.Dir(exe), HelperName)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("sekey: helper path %q must be absolute", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("sekey: the Secure Enclave helper is missing (%w); it ships in the BoundGate app next to boundgate-node, or set sekey_helper", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("sekey: %s is not an executable file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("sekey: %s is writable by group or others (%s); refusing to run it", path, fi.Mode().Perm())
	}
	return path, nil
}

// call runs the helper once. The blob goes in on stdin (base64), never on the
// command line; the answer is one JSON object of base64 values.
func call(ctx context.Context, helper string, blob []byte, args ...string) (map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, args...)
	cmd.Env = []string{} // nothing of the daemon's environment
	if blob != nil {
		cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(blob))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	out := map[string][]byte{}
	if len(bytes.TrimSpace(stdout.Bytes())) == 0 {
		return out, nil // "available" answers with its exit status alone
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("unreadable answer from %s: %w", filepath.Base(helper), err)
	}
	return out, nil
}

func writeBlob(path string, f blobFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("sekey: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("sekey: %w", err)
	}
	return nil
}
