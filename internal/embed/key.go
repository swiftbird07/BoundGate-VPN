package embed

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// platformKey is the device key held by the app (Secure Enclave, Android
// Keystore): the core only ever sees the public key and asks for signatures.
type platformKey struct {
	k   Key
	pub crypto.PublicKey
}

func newPlatformKey(k Key) (*platformKey, error) {
	der, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("embed: device key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("embed: device key: %w", err)
	}
	if err := devicekey.CheckPublicKey(pub); err != nil {
		return nil, err
	}
	return &platformKey{k: k, pub: pub}, nil
}

func (k *platformKey) Public() crypto.PublicKey { return k.pub }

// Sign signs a SHA-256 digest: TLS 1.3 client authentication and the device
// certificate use nothing else with P-256.
func (k *platformKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("embed: the device key signs SHA-256 digests only")
	}
	return k.k.Sign(digest)
}

func (k *platformKey) HardwareBound() bool { return k.k.HardwareBound() }
func (k *platformKey) Kind() string        { return k.k.KeyKind() }
