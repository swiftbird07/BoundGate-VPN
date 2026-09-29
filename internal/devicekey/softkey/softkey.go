// Package softkey is a file-backed DeviceKey for development, tests and
// platforms without a hardware key provider yet (macOS until the Secure
// Enclave helper exists). It is NOT hardware-bound: anyone who can read the
// file can clone the device identity. HardwareBound() therefore returns false
// and policies can require hardware-bound devices to exclude it.
package softkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/safefile"
)

const pemType = "EC PRIVATE KEY"

// Key is an ECDSA P-256 key stored as PEM on disk.
type Key struct {
	priv *ecdsa.PrivateKey
}

var _ devicekey.DeviceKey = (*Key)(nil)

// Public implements crypto.Signer.
func (k *Key) Public() crypto.PublicKey { return &k.priv.PublicKey }

// Sign implements crypto.Signer.
func (k *Key) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.priv.Sign(r, digest, opts)
}

// HardwareBound implements devicekey.DeviceKey: always false.
func (k *Key) HardwareBound() bool { return false }

// Kind implements devicekey.DeviceKey.
func (k *Key) Kind() string { return "softkey" }

// Opener creates the key file on first use and loads it afterwards.
type Opener struct {
	Path string
}

// New returns an Opener for the given file path.
func New(path string) Opener { return Opener{Path: path} }

// Open implements devicekey.Opener.
func (o Opener) Open(ctx context.Context) (devicekey.DeviceKey, error) {
	if o.Path == "" {
		return nil, errors.New("softkey: empty path")
	}
	// the file must be this user's own, not a link someone who can write
	// the directory put there (safefile, docs/PRIVSEP.md)
	b, err := safefile.ReadOwn(o.Path, 64<<10)
	switch {
	case err == nil:
		return load(b)
	case errors.Is(err, os.ErrNotExist):
		return create(o.Path)
	default:
		return nil, fmt.Errorf("softkey: read %s: %w", o.Path, err)
	}
}

func load(b []byte) (*Key, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != pemType {
		return nil, errors.New("softkey: file is not an EC PRIVATE KEY PEM")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("softkey: parse key: %w", err)
	}
	if err := devicekey.CheckPublicKey(&priv.PublicKey); err != nil {
		return nil, err
	}
	return &Key{priv: priv}, nil
}

func create(path string) (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("softkey: generate: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("softkey: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("softkey: mkdir: %w", err)
	}
	// atomically with 0600, so a crash never leaves a half-written or
	// world-readable key behind
	if err := safefile.WriteAtomic(path, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})); err != nil {
		return nil, fmt.Errorf("softkey: write: %w", err)
	}
	return &Key{priv: priv}, nil
}
