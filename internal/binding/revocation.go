package binding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// RevocationNamespace is the SSHSIG namespace of revocations: a signature
// over a binding or a signer set never reads as one.
const RevocationNamespace = "boundgate-revocation"

// RevocationType is the constant `type` field of a revocation.
const RevocationType = "boundgate-revocation"

// Revocation is an admin's signed statement that a node and its key are
// revoked as of Issued. The control plane's DELETE takes effect at once
// (hubs close the tunnels on the next snapshot); this statement is what
// makes it stick against the control plane itself: a node that verified it
// refuses every binding of that node issued before it, for good, so a
// control plane cannot bring the node back by serving its old binding. An
// admin who approves the node again signs a newer binding.
//
// The field order is the canonical JSON order.
type Revocation struct {
	Type       string             `json:"type"`
	NodeID     string             `json:"node_id"`
	SPKI       devicekey.SPKIHash `json:"spki"`
	Deployment string             `json:"deployment,omitempty"`
	Issued     int64              `json:"issued"`
}

// Validate checks that the revocation is complete.
func (r Revocation) Validate() error {
	switch {
	case r.Type != RevocationType:
		return fmt.Errorf("revocation: type %q", r.Type)
	case r.NodeID == "":
		return errors.New("revocation: node_id is empty")
	case r.SPKI.IsZero():
		return errors.New("revocation: spki is empty")
	case r.Deployment != "" && !isHash(r.Deployment):
		return errors.New("revocation: deployment must be a hex SHA-256")
	case r.Issued <= 0:
		return errors.New("revocation: issued must be positive")
	}
	return nil
}

// Canonical returns the bytes that are signed.
func (r Revocation) Canonical() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ParseRevocation decodes canonical bytes and refuses anything that does not
// re-encode to exactly the same bytes.
func ParseRevocation(raw []byte) (Revocation, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Revocation
	if err := dec.Decode(&r); err != nil {
		return Revocation{}, fmt.Errorf("revocation: %w", err)
	}
	if dec.More() {
		return Revocation{}, errors.New("revocation: trailing data")
	}
	again, err := r.Canonical()
	if err != nil {
		return Revocation{}, err
	}
	if !bytes.Equal(again, raw) {
		return Revocation{}, errors.New("revocation: not in canonical form")
	}
	return r, nil
}

// VerifyRevocation checks the signature of a revocation by a pinned admin
// key and, with a guard, that it is for this network, and hands it to the
// guard. It returns what it could parse, also on error.
func VerifyRevocation(sr registry.SignedRevocation, signers Signers, g Guard) (Revocation, error) {
	r, err := ParseRevocation([]byte(sr.Revocation))
	if err != nil {
		return r, err
	}
	if strings.TrimSpace(sr.Signature) == "" {
		return r, ErrNoSignature
	}
	sig, err := ParseSSHSIG(sr.Signature)
	if err != nil {
		return r, err
	}
	if sig.Namespace != RevocationNamespace {
		return r, fmt.Errorf("%w: namespace %q", ErrBadSignature, sig.Namespace)
	}
	if err := CheckSignerType(sig.PublicKey); err != nil {
		return r, err
	}
	if !signers.Contains(sig.PublicKey) {
		return r, ErrUnknownSigner
	}
	if err := sig.Verify([]byte(sr.Revocation)); err != nil {
		return r, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if g != nil {
		if dep := g.Deployment(); dep != "" && r.Deployment != "" && r.Deployment != dep {
			return r, ErrOtherDeployment
		}
		g.Revoke(r)
	}
	return r, nil
}

// SignRevocation signs canonical revocation bytes (tests and the CLI's
// key-file path).
func SignRevocation(signer ssh.Signer, canonical []byte) (string, error) {
	return Sign(signer, RevocationNamespace, canonical)
}
