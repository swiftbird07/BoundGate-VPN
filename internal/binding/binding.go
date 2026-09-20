// Package binding defines the admin-signed node binding: the statement
// "this node id and this key hold these roles, prefixes and overlay address",
// signed by an administrator's SSH key (ideally a FIDO2 sk-key on a YubiKey)
// in OpenSSH's SSHSIG format. Every node verifies the bindings of its peers
// and its own binding against the admin keys it pinned at enrollment, so a
// compromised control plane cannot invent nodes or upgrade a node to a hub.
//
// This package is part of the security TCB (docs/TCB.md): it is the only
// code that verifies bindings. It depends on x/crypto/ssh for the signature
// primitives and does not import the control plane or the node.
package binding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// Namespace is the SSHSIG namespace; a signature made for any other purpose
// does not verify as a binding.
const Namespace = "boundgate-binding"

// Binding is the signed statement. The field order is the canonical JSON
// order; roles and prefixes are sorted so two admins produce the same bytes
// for the same decision.
type Binding struct {
	NodeID     string             `json:"node_id"`
	SPKI       devicekey.SPKIHash `json:"spki"`
	KeyVersion int                `json:"key_version"`
	Kind       registry.Kind      `json:"kind"`
	Roles      []registry.Role    `json:"roles"`
	Prefixes   []registry.Prefix  `json:"prefixes"`
	OverlayIP  netip.Addr         `json:"overlay_ip"`
	// HardwareBound: the admin vouches that the key lives in a TPM. Left out
	// when false, so bindings signed before the field existed stay valid and
	// mean what they always meant: not hardware-bound.
	HardwareBound bool `json:"hardware_bound,omitempty"`
	// Tags are the administrator's labels. Policies select nodes by them
	// ("laptops reach production"), so they decide what a node may do just as
	// roles do, and the control plane must not be able to hand them out by
	// itself. Left out when empty: bindings signed before tags existed stay
	// valid and mean "no tags".
	Tags []string `json:"tags,omitempty"`
}

// FromNode builds the binding a node record must be signed for.
func FromNode(n registry.Node) Binding {
	return Binding{NodeID: string(n.ID), SPKI: n.SPKI, KeyVersion: n.KeyVersion, Kind: n.Kind, Roles: n.Roles, Prefixes: n.Prefixes, OverlayIP: n.OverlayIP, HardwareBound: n.HardwareBound, Tags: n.Tags}
}

// Normalize sorts roles, prefixes and tags and masks prefixes.
func (b Binding) Normalize() Binding {
	roles := slices.Clone(b.Roles)
	slices.Sort(roles)
	roles = slices.Compact(roles)
	prefixes := make([]registry.Prefix, 0, len(b.Prefixes))
	for _, p := range b.Prefixes {
		prefixes = append(prefixes, registry.Prefix{Prefix: p.Prefix.Masked(), Mode: p.Mode})
	}
	slices.SortFunc(prefixes, func(a, c registry.Prefix) int {
		if r := strings.Compare(a.Prefix.String(), c.Prefix.String()); r != 0 {
			return r
		}
		return strings.Compare(string(a.Mode), string(c.Mode))
	})
	prefixes = slices.CompactFunc(prefixes, func(a, c registry.Prefix) bool { return a == c })
	if roles == nil {
		roles = []registry.Role{}
	}
	if b.Kind == "" {
		b.Kind = registry.KindInteractive
	}
	b.Roles, b.Prefixes = roles, prefixes
	tags := slices.Clone(b.Tags)
	slices.Sort(tags)
	tags = slices.Compact(tags)
	if len(tags) == 0 {
		tags = nil // omitted, like in every binding from before there were tags
	}
	b.Tags = tags
	return b
}

// Validate checks that the binding is complete.
func (b Binding) Validate() error {
	if b.NodeID == "" {
		return errors.New("binding: node_id is empty")
	}
	if b.SPKI.IsZero() {
		return errors.New("binding: spki is empty")
	}
	if b.KeyVersion <= 0 {
		return errors.New("binding: key_version must be positive")
	}
	if _, err := registry.ParseKind(string(b.Kind)); err != nil {
		return err
	}
	if len(b.Roles) == 0 {
		return errors.New("binding: at least one role is required")
	}
	if _, err := registry.ParseRoles(roleNames(b.Roles)); err != nil {
		return err
	}
	for _, p := range b.Prefixes {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	if !b.OverlayIP.IsValid() || !b.OverlayIP.Is4() {
		return errors.New("binding: overlay_ip must be an IPv4 address")
	}
	return nil
}

func roleNames(rs []registry.Role) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// Canonical returns the bytes that are signed: normalized, compact JSON
// with the fields in struct order and no HTML escaping.
func (b Binding) Canonical() ([]byte, error) {
	b = b.Normalize()
	if err := b.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Parse decodes canonical bytes and refuses anything that does not
// re-encode to exactly the same bytes (unknown fields, reordering, spacing).
func Parse(raw []byte) (Binding, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Binding
	if err := dec.Decode(&b); err != nil {
		return Binding{}, fmt.Errorf("binding: %w", err)
	}
	if dec.More() {
		return Binding{}, errors.New("binding: trailing data")
	}
	again, err := b.Canonical()
	if err != nil {
		return Binding{}, err
	}
	if !bytes.Equal(again, raw) {
		return Binding{}, errors.New("binding: not in canonical form")
	}
	return b, nil
}

// Matches reports whether the node record carries exactly what the binding
// says. Unsigned fields (name, public address, platform) are not compared.
func (b Binding) Matches(n registry.Node) error {
	b = b.Normalize()
	want := FromNode(n).Normalize()
	switch {
	case b.NodeID != want.NodeID:
		return fmt.Errorf("binding: node id %q, record says %q", b.NodeID, want.NodeID)
	case b.SPKI != want.SPKI:
		return errors.New("binding: key does not match the record")
	case b.KeyVersion != want.KeyVersion:
		return fmt.Errorf("binding: key version %d, record says %d", b.KeyVersion, want.KeyVersion)
	case b.Kind != want.Kind:
		return fmt.Errorf("binding: kind %s, record says %s", b.Kind, want.Kind)
	case !slices.Equal(b.Roles, want.Roles):
		return fmt.Errorf("binding: roles %v, record says %v", b.Roles, want.Roles)
	case !slices.Equal(b.Prefixes, want.Prefixes):
		return fmt.Errorf("binding: prefixes %v, record says %v", b.Prefixes, want.Prefixes)
	case b.HardwareBound != want.HardwareBound:
		return fmt.Errorf("binding: hardware_bound %v, record says %v", b.HardwareBound, want.HardwareBound)
	case !slices.Equal(b.Tags, want.Tags):
		return fmt.Errorf("binding: tags %v, record says %v", b.Tags, want.Tags)
	case b.OverlayIP != want.OverlayIP:
		return fmt.Errorf("binding: overlay ip %s, record says %s", b.OverlayIP, want.OverlayIP)
	}
	return nil
}

// Signers is the set of admin public keys a verifier accepts.
type Signers []ssh.PublicKey

// ParseSigners reads authorized_keys lines (comments and blank lines are
// skipped). Every key must be of an allowed type.
func ParseSigners(text []byte) (Signers, error) {
	var out Signers
	for len(text) > 0 {
		var line []byte
		if i := bytes.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			line, text = text, nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("binding: admin key: %w", err)
		}
		if err := CheckSignerType(pub); err != nil {
			return nil, err
		}
		out = append(out, pub)
	}
	return out, nil
}

// AllowedKeyTypes are the SSH key types accepted for admin signatures.
var AllowedKeyTypes = []string{ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256}

// CheckSignerType refuses key types outside AllowedKeyTypes (no RSA, no
// DSA, no certificates).
func CheckSignerType(pub ssh.PublicKey) error {
	if !slices.Contains(AllowedKeyTypes, pub.Type()) {
		return fmt.Errorf("binding: key type %s is not allowed (want one of %s)", pub.Type(), strings.Join(AllowedKeyTypes, ", "))
	}
	return nil
}

// IsHardwareKey reports whether the key is a FIDO2 security-key type.
func IsHardwareKey(pub ssh.PublicKey) bool {
	return pub.Type() == ssh.KeyAlgoSKED25519 || pub.Type() == ssh.KeyAlgoSKECDSA256
}

// Contains reports whether pub is one of the signers.
func (s Signers) Contains(pub ssh.PublicKey) bool {
	want := pub.Marshal()
	for _, k := range s {
		if bytes.Equal(k.Marshal(), want) {
			return true
		}
	}
	return false
}

// Fingerprints lists the signers as "type SHA256:... " strings.
func (s Signers) Fingerprints() []string {
	out := make([]string, 0, len(s))
	for _, k := range s {
		out = append(out, k.Type()+" "+ssh.FingerprintSHA256(k))
	}
	return out
}

// Errors from verification.
var (
	ErrNoSignature   = errors.New("binding: node has no signature")
	ErrUnknownSigner = errors.New("binding: signed by a key that is not a pinned admin key")
	ErrBadSignature  = errors.New("binding: signature does not verify")
)

// Verify checks that armored (an SSHSIG) is a valid signature over raw by
// one of the signers. It returns the signing key.
func Verify(raw []byte, armored string, signers Signers) (ssh.PublicKey, error) {
	if strings.TrimSpace(armored) == "" {
		return nil, ErrNoSignature
	}
	sig, err := ParseSSHSIG(armored)
	if err != nil {
		return nil, err
	}
	if sig.Namespace != Namespace {
		return nil, fmt.Errorf("%w: namespace %q", ErrBadSignature, sig.Namespace)
	}
	if err := CheckSignerType(sig.PublicKey); err != nil {
		return nil, err
	}
	if !signers.Contains(sig.PublicKey) {
		return nil, ErrUnknownSigner
	}
	if err := sig.Verify(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return sig.PublicKey, nil
}

// VerifyNode checks a node record: the canonical binding it carries must be
// signed by a pinned admin key and must say exactly what the record says.
func VerifyNode(n registry.Node, signers Signers) (ssh.PublicKey, error) {
	if n.Binding == "" {
		return nil, ErrNoSignature
	}
	b, err := Parse([]byte(n.Binding))
	if err != nil {
		return nil, err
	}
	if err := b.Matches(n); err != nil {
		return nil, err
	}
	return Verify([]byte(n.Binding), n.Signature, signers)
}

// Rejected is a peer that was dropped from a snapshot.
type Rejected struct {
	ID   string
	Name string
	Err  error
}

// VerifySnapshot verifies the node's own record (an error means the node
// must not operate) and removes every peer whose binding does not verify.
// It returns the rejected peers. The snapshot must be re-indexed afterwards
// (Holder.Store does that).
func VerifySnapshot(s *registry.Snapshot, signers Signers) ([]Rejected, error) {
	if len(signers) == 0 {
		return nil, errors.New("binding: no admin keys pinned; re-enroll this node")
	}
	if s.Self.ID != "" {
		if _, err := VerifyNode(s.Self, signers); err != nil {
			return nil, fmt.Errorf("own binding: %w", err)
		}
	}
	var rejected []Rejected
	kept := s.Peers[:0]
	for _, p := range s.Peers {
		if _, err := VerifyNode(p, signers); err != nil {
			rejected = append(rejected, Rejected{ID: string(p.ID), Name: p.Name, Err: err})
			continue
		}
		kept = append(kept, p)
	}
	for i := len(kept); i < len(s.Peers); i++ {
		s.Peers[i] = registry.Node{}
	}
	s.Peers = kept
	return rejected, nil
}
