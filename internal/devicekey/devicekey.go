// Package devicekey defines the device identity key: a signing key that never
// leaves the device. Every other component only sees crypto.Signer.
//
// This package is part of the security TCB (see docs/TCB.md). It must stay
// small and must not import anything from the policy, control-plane or agent
// layers.
package devicekey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// DeviceKey is the hardware-bound (or, for development, software) identity
// key of a device. Sign must be usable from crypto/tls for TLS 1.3 client
// authentication, which means ECDSA P-256 with SHA-256.
type DeviceKey interface {
	crypto.Signer
	// HardwareBound reports whether the private key is protected by hardware
	// (TPM, Secure Enclave) and cannot be exported. Software keys return false.
	HardwareBound() bool
	// Kind names the implementation: "softkey", "tpm2", "secure-enclave".
	Kind() string
}

// Opener creates or loads a device key. Implementations must be idempotent:
// calling Open twice on the same store yields the same public key.
type Opener interface {
	Open(ctx context.Context) (DeviceKey, error)
}

// SPKIHash is the SHA-256 digest of the DER-encoded PKIX SubjectPublicKeyInfo.
// It is the stable identifier of a device key in the registry and in logs.
type SPKIHash [sha256.Size]byte

// HashPublicKey computes the SPKIHash of a public key.
func HashPublicKey(pub crypto.PublicKey) (SPKIHash, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return SPKIHash{}, fmt.Errorf("devicekey: marshal public key: %w", err)
	}
	return sha256.Sum256(der), nil
}

// String returns the lowercase hex encoding.
func (h SPKIHash) String() string { return hex.EncodeToString(h[:]) }

// Fingerprint returns a human-comparable form (groups of four hex digits),
// shown by the CLI at enrollment and by the admin UI before approval.
func (h SPKIHash) Fingerprint() string {
	s := h.String()
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i : i+4])
	}
	return b.String()
}

// IsZero reports whether the hash is unset.
func (h SPKIHash) IsZero() bool { return h == SPKIHash{} }

// ParseSPKIHash parses the hex form produced by String or Fingerprint.
func ParseSPKIHash(s string) (SPKIHash, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return SPKIHash{}, errors.New("devicekey: invalid SPKI hash")
	}
	var h SPKIHash
	copy(h[:], b)
	return h, nil
}

// MarshalText implements encoding.TextMarshaler (hex).
func (h SPKIHash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *SPKIHash) UnmarshalText(b []byte) error {
	p, err := ParseSPKIHash(string(b))
	if err != nil {
		return err
	}
	*h = p
	return nil
}

// CheckPublicKey enforces the only key type BoundGate accepts for device
// identity: ECDSA on P-256. It is used by every peer verifier so that no
// other layer has to reason about key types.
func CheckPublicKey(pub crypto.PublicKey) error {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("devicekey: unsupported key type %T, want ECDSA P-256", pub)
	}
	if ec.Curve != elliptic.P256() {
		return fmt.Errorf("devicekey: unsupported curve %s, want P-256", ec.Curve.Params().Name)
	}
	return nil
}
