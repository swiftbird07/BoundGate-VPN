package binding

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// The admin keys themselves are a signed statement too: a versioned list,
// each version signed by a key of the version before it. A node follows that
// chain from the list it pinned at enrollment, so administrators can add and
// remove keys without re-enrolling anything, and the control plane, which
// only stores and forwards the chain, cannot: it holds no admin key.
//
//	set 1 (genesis)  keys {A}      signed by A   (pinned on first use, or provisioned)
//	set 2            keys {A, B}   signed by A   (a key of set 1)
//	set 3            keys {B}      signed by B   (a key of set 2; A is out)
//
// What a node refuses, whatever the control plane sends: a set signed by a
// key that is not in the node's current set (in particular by a key that only
// the new set contains), a version that is not exactly current+1, a set whose
// `prev` is not the hash of the node's current set (a fork), anything at or
// below the current version that differs from what it has (a rollback), and
// signatures made for another purpose (SSHSIG namespace, `type` field).
// Verification is all-or-nothing: one bad link and the node keeps what it has.

// SignersNamespace is the SSHSIG namespace of signer-set signatures. It
// differs from the binding namespace, so neither kind of signature can stand
// in for the other.
const SignersNamespace = "boundgate-signers"

// SignerSetType is the constant `type` field of a signer set.
const SignerSetType = "boundgate-signer-set"

// MaxSigners bounds the list (and the work a chain can cause).
const MaxSigners = 32

// MaxChain bounds how many links a node processes in one delivery.
const MaxChain = 4096

// SignerSet is one version of the admin key list. The field order is the
// canonical JSON order.
type SignerSet struct {
	Type    string `json:"type"`
	Version uint64 `json:"version"` // 1 is the genesis set
	// Prev is the hex SHA-256 of the previous set's canonical bytes; empty
	// for the genesis set only.
	Prev string `json:"prev"`
	// Keys are "type base64" strings without comment, sorted, unique.
	Keys []string `json:"keys"`
}

// SignedSet is a link of the chain as stored and transported: the canonical
// JSON of a SignerSet and the armored SSHSIG over it.
type SignedSet = registry.SignerLink

// Trust is what a verifier currently accepts: the newest set it has
// verified. The zero value means "nothing pinned".
type Trust struct {
	Version uint64   `json:"version"`
	Hash    string   `json:"hash"` // hex SHA-256 of the canonical set
	Keys    []string `json:"keys"`
}

// Errors from chain verification. All of them leave the verifier's trust
// unchanged.
var (
	ErrSetForm      = errors.New("signer set: malformed")
	ErrSetSigner    = errors.New("signer set: not signed by a key of the previous set")
	ErrSetSignature = errors.New("signer set: signature does not verify")
	ErrSetSequence  = errors.New("signer set: version or previous-hash does not continue the pinned set")
	ErrSetFork      = errors.New("signer set: the chain contradicts the pinned set (fork or rollback)")
)

// KeyString renders a public key the way signer sets list it.
func KeyString(pub ssh.PublicKey) string {
	return pub.Type() + " " + base64.StdEncoding.EncodeToString(pub.Marshal())
}

func parseKeyString(s string) (ssh.PublicKey, error) {
	typ, b64, ok := strings.Cut(s, " ")
	if !ok || strings.ContainsAny(b64, " \t\r\n") {
		return nil, fmt.Errorf("%w: key %q is not \"type base64\"", ErrSetForm, s)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: key %q: %v", ErrSetForm, s, err)
	}
	pub, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: key %q: %v", ErrSetForm, s, err)
	}
	if pub.Type() != typ || KeyString(pub) != s {
		return nil, fmt.Errorf("%w: key %q is not in canonical form", ErrSetForm, s)
	}
	if err := CheckSignerType(pub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSetForm, err)
	}
	return pub, nil
}

// NewSignerSet builds the set that follows prev (nil for the genesis set)
// with the given keys.
func NewSignerSet(prev *Trust, keys Signers) (SignerSet, error) {
	s := SignerSet{Type: SignerSetType, Version: 1}
	if prev != nil && prev.Version > 0 {
		s.Version, s.Prev = prev.Version+1, prev.Hash
	}
	for _, k := range keys {
		s.Keys = append(s.Keys, KeyString(k))
	}
	slices.Sort(s.Keys)
	s.Keys = slices.Compact(s.Keys)
	return s, s.Validate()
}

// Validate checks the form of a set on its own.
func (s SignerSet) Validate() error {
	if s.Type != SignerSetType {
		return fmt.Errorf("%w: type %q", ErrSetForm, s.Type)
	}
	if s.Version == 0 {
		return fmt.Errorf("%w: version 0", ErrSetForm)
	}
	if (s.Version == 1) != (s.Prev == "") {
		return fmt.Errorf("%w: only the genesis set has no previous hash", ErrSetForm)
	}
	if s.Prev != "" {
		if b, err := hex.DecodeString(s.Prev); err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != s.Prev {
			return fmt.Errorf("%w: previous hash", ErrSetForm)
		}
	}
	if len(s.Keys) == 0 {
		return fmt.Errorf("%w: no keys (the list can never become empty)", ErrSetForm)
	}
	if len(s.Keys) > MaxSigners {
		return fmt.Errorf("%w: more than %d keys", ErrSetForm, MaxSigners)
	}
	for i, k := range s.Keys {
		if _, err := parseKeyString(k); err != nil {
			return err
		}
		if i > 0 && s.Keys[i-1] >= k {
			return fmt.Errorf("%w: keys are not sorted and unique", ErrSetForm)
		}
	}
	return nil
}

// Canonical returns the signed bytes.
func (s SignerSet) Canonical() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ParseSignerSet decodes canonical bytes and refuses anything that does not
// re-encode to exactly the same bytes, so a set has exactly one hash.
func ParseSignerSet(raw []byte) (SignerSet, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s SignerSet
	if err := dec.Decode(&s); err != nil {
		return SignerSet{}, fmt.Errorf("%w: %v", ErrSetForm, err)
	}
	if dec.More() {
		return SignerSet{}, fmt.Errorf("%w: trailing data", ErrSetForm)
	}
	again, err := s.Canonical()
	if err != nil {
		return SignerSet{}, err
	}
	if !bytes.Equal(again, raw) {
		return SignerSet{}, fmt.Errorf("%w: not in canonical form", ErrSetForm)
	}
	return s, nil
}

// HashSet is the chain hash of canonical set bytes.
func HashSet(canonical []byte) string {
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:])
}

// Signers returns the trusted keys for binding verification.
func (t Trust) Signers() (Signers, error) {
	out := make(Signers, 0, len(t.Keys))
	for _, k := range t.Keys {
		pub, err := parseKeyString(k)
		if err != nil {
			return nil, err
		}
		out = append(out, pub)
	}
	return out, nil
}

// Pinned reports whether the verifier trusts anything yet.
func (t Trust) Pinned() bool { return len(t.Keys) > 0 }

// verifyLink checks one link against the keys allowed to sign it and
// returns the trust it establishes.
func verifyLink(l SignedSet, allowed []string) (SignerSet, Trust, ssh.PublicKey, error) {
	set, err := ParseSignerSet([]byte(l.Set))
	if err != nil {
		return SignerSet{}, Trust{}, nil, err
	}
	sig, err := ParseSSHSIG(l.Signature)
	if err != nil {
		return SignerSet{}, Trust{}, nil, fmt.Errorf("%w: %v", ErrSetSignature, err)
	}
	if sig.Namespace != SignersNamespace {
		return SignerSet{}, Trust{}, nil, fmt.Errorf("%w: namespace %q", ErrSetSignature, sig.Namespace)
	}
	if err := CheckSignerType(sig.PublicKey); err != nil {
		return SignerSet{}, Trust{}, nil, fmt.Errorf("%w: %v", ErrSetSigner, err)
	}
	if !slices.Contains(allowed, KeyString(sig.PublicKey)) {
		return SignerSet{}, Trust{}, nil, ErrSetSigner
	}
	if err := sig.Verify([]byte(l.Set)); err != nil {
		return SignerSet{}, Trust{}, nil, fmt.Errorf("%w: %v", ErrSetSignature, err)
	}
	return set, Trust{Version: set.Version, Hash: HashSet([]byte(l.Set)), Keys: set.Keys}, sig.PublicKey, nil
}

// VerifyChain advances cur along chain and returns the new trust. chain is
// a run of consecutive links, oldest first. On any error the returned trust
// is cur, unchanged: verification is all-or-nothing.
//
//   - Nothing pinned: the chain must start at the genesis set, which is
//     signed by one of its own keys, and verify link by link; its last set
//     is pinned. With genesis != "" the genesis set must have that hash (the
//     operator provisioned it); otherwise this is trust on first use, as for
//     the control plane's key.
//   - A pinned set: the chain must contain the pinned set byte for byte at
//     its version (no fork, no rollback), and every later link must be signed
//     by a key of the set before it. Links older than the pin are history
//     the verifier does not rely on and does not look at.
func VerifyChain(cur Trust, chain []SignedSet, genesis string) (Trust, error) {
	if len(chain) == 0 {
		return cur, nil
	}
	if len(chain) > MaxChain {
		return cur, fmt.Errorf("%w: chain of %d links", ErrSetForm, len(chain))
	}
	run := cur
	start := 0
	if cur.Pinned() {
		start = -1
		for i, l := range chain {
			set, err := ParseSignerSet([]byte(l.Set))
			if err != nil {
				return cur, fmt.Errorf("link %d: %w", i+1, err)
			}
			if set.Version != cur.Version {
				continue
			}
			if HashSet([]byte(l.Set)) != cur.Hash {
				return cur, fmt.Errorf("%w: version %d is not the pinned set", ErrSetFork, cur.Version)
			}
			start = i + 1
			break
		}
		if start < 0 {
			return cur, fmt.Errorf("%w: the chain does not contain the pinned version %d", ErrSetFork, cur.Version)
		}
	}
	for i := start; i < len(chain); i++ {
		l := chain[i]
		set, err := ParseSignerSet([]byte(l.Set))
		if err != nil {
			return cur, fmt.Errorf("link %d: %w", i+1, err)
		}
		allowed := run.Keys
		if !run.Pinned() {
			// first link for a verifier without a pin: the genesis set
			if set.Version != 1 {
				return cur, fmt.Errorf("link %d: %w: nothing is pinned and the chain starts at version %d", i+1, ErrSetSequence, set.Version)
			}
			if genesis != "" && HashSet([]byte(l.Set)) != genesis {
				return cur, fmt.Errorf("link %d: %w: genesis set is not the provisioned one", i+1, ErrSetFork)
			}
			allowed = set.Keys
		} else if set.Version != run.Version+1 || set.Prev != run.Hash {
			return cur, fmt.Errorf("link %d: %w: version %d after %d", i+1, ErrSetSequence, set.Version, run.Version)
		}
		_, next, _, err := verifyLink(l, allowed)
		if err != nil {
			return cur, fmt.Errorf("link %d (version %d): %w", i+1, set.Version, err)
		}
		run = next
	}
	return run, nil
}

// SignSet signs canonical set bytes (tests and the CLI's key-file path).
func SignSet(signer ssh.Signer, canonical []byte) (string, error) {
	return Sign(signer, SignersNamespace, canonical)
}
