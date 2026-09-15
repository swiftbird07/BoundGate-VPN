package binding

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHSIG is OpenSSH's detached signature format (PROTOCOL.sshsig). It is
// what `ssh-keygen -Y sign` produces and `ssh-keygen -Y verify` checks, so
// admins can sign with the OpenSSH tooling they already have, including
// FIDO2 security keys.
//
// Armored form:
//
//	-----BEGIN SSH SIGNATURE-----
//	base64(blob)
//	-----END SSH SIGNATURE-----
//
// blob = "SSHSIG" || uint32 version=1 || string publickey || string namespace
//
//	|| string reserved || string hash_algorithm || string signature
//
// The signature itself is over
//
//	"SSHSIG" || string namespace || string reserved || string hash_algorithm
//	|| string H(message)
//
// where H is the named hash (sha256 or sha512) of the message.
type SSHSIG struct {
	PublicKey ssh.PublicKey
	Namespace string
	HashAlg   string
	Signature *ssh.Signature
}

const (
	sshsigMagic   = "SSHSIG"
	sshsigVersion = 1
	armorBegin    = "-----BEGIN SSH SIGNATURE-----"
	armorEnd      = "-----END SSH SIGNATURE-----"
)

// wire layout of the blob after the 6-byte magic
type sshsigBlob struct {
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

// wire layout of the data that is signed, after the magic
type sshsigSignedData struct {
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      []byte
}

func hashFor(alg string) (hash.Hash, error) {
	switch alg {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("sshsig: unsupported hash algorithm %q", alg)
	}
}

// signedData builds the bytes the key signs.
func signedData(namespace, hashAlg string, message []byte) ([]byte, error) {
	h, err := hashFor(hashAlg)
	if err != nil {
		return nil, err
	}
	h.Write(message)
	body := ssh.Marshal(sshsigSignedData{Namespace: namespace, HashAlg: hashAlg, Hash: h.Sum(nil)})
	return append([]byte(sshsigMagic), body...), nil
}

// Sign produces an armored SSHSIG over message with signer (an ssh-agent
// key, a file key, or an sk-key through the agent). The hash algorithm is
// sha512 like ssh-keygen's default.
func Sign(signer ssh.Signer, namespace string, message []byte) (string, error) {
	if err := CheckSignerType(signer.PublicKey()); err != nil {
		return "", err
	}
	data, err := signedData(namespace, "sha512", message)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return "", fmt.Errorf("sshsig: sign: %w", err)
	}
	return Armor(&SSHSIG{PublicKey: signer.PublicKey(), Namespace: namespace, HashAlg: "sha512", Signature: sig}), nil
}

// Armor encodes the signature in the PEM-like OpenSSH form.
func Armor(s *SSHSIG) string {
	body := ssh.Marshal(sshsigBlob{
		Version:   sshsigVersion,
		PublicKey: s.PublicKey.Marshal(),
		Namespace: s.Namespace,
		HashAlg:   s.HashAlg,
		Signature: ssh.Marshal(s.Signature),
	})
	b64 := base64.StdEncoding.EncodeToString(append([]byte(sshsigMagic), body...))
	var sb strings.Builder
	sb.WriteString(armorBegin + "\n")
	for len(b64) > 70 {
		sb.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	sb.WriteString(b64 + "\n" + armorEnd + "\n")
	return sb.String()
}

// ParseSSHSIG decodes an armored signature. It does not verify anything.
func ParseSSHSIG(armored string) (*SSHSIG, error) {
	text := strings.TrimSpace(armored)
	if !strings.HasPrefix(text, armorBegin) || !strings.HasSuffix(text, armorEnd) {
		return nil, errors.New("sshsig: not an armored SSH signature")
	}
	text = strings.TrimSuffix(strings.TrimPrefix(text, armorBegin), armorEnd)
	text = strings.Join(strings.Fields(text), "")
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("sshsig: base64: %w", err)
	}
	if len(raw) < len(sshsigMagic) || string(raw[:len(sshsigMagic)]) != sshsigMagic {
		return nil, errors.New("sshsig: bad magic")
	}
	var blob sshsigBlob
	if err := ssh.Unmarshal(raw[len(sshsigMagic):], &blob); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	if blob.Version != sshsigVersion {
		return nil, fmt.Errorf("sshsig: unsupported version %d", blob.Version)
	}
	if blob.Reserved != "" {
		return nil, errors.New("sshsig: reserved field is not empty")
	}
	if _, err := hashFor(blob.HashAlg); err != nil {
		return nil, err
	}
	pub, err := ssh.ParsePublicKey(blob.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshsig: public key: %w", err)
	}
	sig, err := parseSignature(blob.Signature)
	if err != nil {
		return nil, err
	}
	return &SSHSIG{PublicKey: pub, Namespace: blob.Namespace, HashAlg: blob.HashAlg, Signature: sig}, nil
}

// parseSignature decodes string format || string blob || rest.
func parseSignature(raw []byte) (*ssh.Signature, error) {
	var w struct {
		Format string
		Blob   []byte
		Rest   []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sshsig: signature: %w", err)
	}
	if w.Format == "" || len(w.Blob) == 0 {
		return nil, errors.New("sshsig: empty signature")
	}
	return &ssh.Signature{Format: w.Format, Blob: w.Blob, Rest: w.Rest}, nil
}

// Verify checks the signature over message. The key type in the signature
// must match the embedded public key (x/crypto enforces that, and for
// sk-keys also the user-presence flag).
func (s *SSHSIG) Verify(message []byte) error {
	data, err := signedData(s.Namespace, s.HashAlg, message)
	if err != nil {
		return err
	}
	if !algorithmMatches(s.PublicKey.Type(), s.Signature.Format) {
		return fmt.Errorf("sshsig: signature algorithm %s does not fit key type %s", s.Signature.Format, s.PublicKey.Type())
	}
	return s.PublicKey.Verify(data, s.Signature)
}

// algorithmMatches pins the signature algorithm to the key type so a
// weaker algorithm cannot be substituted.
func algorithmMatches(keyType, sigFormat string) bool {
	return keyType == sigFormat
}
