// Package tpm2key is a DeviceKey held by a TPM 2.0: an ECDSA P-256 signing
// key created inside the TPM with fixedTPM, fixedParent and
// sensitiveDataOrigin, so the private part never existed outside of it and
// cannot be duplicated to another TPM. What lies in the state directory is
// the key blob wrapped by the TPM's storage root key; it is useless on any
// other machine.
//
// This package is part of the security TCB (docs/TCB.md).
package tpm2key

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// Kind is the key kind reported at enrollment.
const Kind = "tpm2"

// keyTemplate is the device key: unrestricted ECDSA P-256 signing key with
// the scheme fixed to SHA-256, which is all TLS 1.3 and the device
// certificate need. No password: the key is bound to the machine, not to a
// person (the person is OIDC's business).
var keyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		CurveID: tpm2.TPMECCNistP256,
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
	}),
}

// blobFile is the on-disk form of the wrapped key.
type blobFile struct {
	Version int    `json:"version"`
	Parent  string `json:"parent"` // how the parent is derived; only "owner-ecc-srk"
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

const parentOwnerSRK = "owner-ecc-srk"

// Opener creates the key on first use and loads it afterwards.
type Opener struct {
	// Device is the TPM: a device path (default /dev/tpmrm0) or
	// unix:PATH / tcp:HOST:PORT for swtpm.
	Device string
	// Path is the key blob file.
	Path string
}

// New returns an Opener.
func New(device, path string) Opener { return Opener{Device: device, Path: path} }

// Key is a loaded TPM key. It holds the TPM connection for its lifetime.
type Key struct {
	mu     sync.Mutex
	tpm    transport.TPMCloser
	handle tpm2.NamedHandle
	pub    *ecdsa.PublicKey
}

var _ devicekey.DeviceKey = (*Key)(nil)

// Open implements devicekey.Opener.
func (o Opener) Open(ctx context.Context) (devicekey.DeviceKey, error) {
	if o.Path == "" {
		return nil, errors.New("tpm2key: empty path")
	}
	tpm, raw, err := openTPM(o.Device)
	if err != nil {
		return nil, err
	}
	k, err := open(tpm, raw, o.Path)
	if err != nil {
		tpm.Close()
		return nil, err
	}
	return k, nil
}

func open(tpm transport.TPMCloser, raw bool, path string) (*Key, error) {
	if raw {
		// Without a resource manager the objects of a process that died stay
		// loaded, and a TPM has room for about three. A socket TPM belongs to
		// this node alone, so what is loaded is ours.
		if err := flushTransient(tpm); err != nil {
			return nil, err
		}
	}
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2key: storage root key: %w", err)
	}
	defer flush(tpm, srk.ObjectHandle)
	parent := tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name}

	var blob blobFile
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &blob); err != nil {
			return nil, fmt.Errorf("tpm2key: %s: %w", path, err)
		}
		if blob.Version != 1 || blob.Parent != parentOwnerSRK {
			return nil, fmt.Errorf("tpm2key: %s: unsupported key file (version %d, parent %q)", path, blob.Version, blob.Parent)
		}
	case errors.Is(err, os.ErrNotExist):
		created, err := tpm2.Create{ParentHandle: parent, InPublic: tpm2.New2B(keyTemplate)}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("tpm2key: create key: %w", err)
		}
		blob = blobFile{Version: 1, Parent: parentOwnerSRK, Public: created.OutPublic.Bytes(), Private: created.OutPrivate.Buffer}
		if err := writeBlob(path, blob); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("tpm2key: read %s: %w", path, err)
	}

	public := tpm2.BytesAs2B[tpm2.TPMTPublic](blob.Public)
	// Load fails unless this TPM wrapped the blob: that is the binding.
	loaded, err := tpm2.Load{ParentHandle: parent, InPrivate: tpm2.TPM2BPrivate{Buffer: blob.Private}, InPublic: public}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2key: load key (was %s created on this TPM?): %w", path, err)
	}
	pub, err := checkPublic(public)
	if err != nil {
		flush(tpm, loaded.ObjectHandle)
		return nil, err
	}
	return &Key{tpm: tpm, handle: tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name}, pub: pub}, nil
}

// checkPublic makes sure the key is what HardwareBound claims: created in
// the TPM, fixed to it, and of the one accepted type. The TPM has verified
// on Load that the public area belongs to the private blob.
func checkPublic(public tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	p, err := public.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm2key: public area: %w", err)
	}
	a := p.ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || a.EncryptedDuplication || !a.SignEncrypt || a.Decrypt || a.Restricted {
		return nil, errors.New("tpm2key: key attributes do not describe a TPM-generated, non-duplicable signing key")
	}
	parms, err := p.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("tpm2key: not an ECC key: %w", err)
	}
	point, err := p.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm2key: %w", err)
	}
	pub, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, fmt.Errorf("tpm2key: %w", err)
	}
	if err := devicekey.CheckPublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// Public implements crypto.Signer.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Sign implements crypto.Signer: ECDSA over a SHA-256 digest, ASN.1 DER.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("tpm2key: only SHA-256 digests can be signed")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.tpm == nil {
		return nil, errors.New("tpm2key: key is closed")
	}
	rsp, err := tpm2.Sign{
		KeyHandle: k.handle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(k.tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2key: sign: %w", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpm2key: signature: %w", err)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer)})
}

// HardwareBound implements devicekey.DeviceKey.
func (k *Key) HardwareBound() bool { return true }

// Kind implements devicekey.DeviceKey.
func (k *Key) Kind() string { return Kind }

// Close unloads the key and releases the TPM.
func (k *Key) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.tpm == nil {
		return nil
	}
	flush(k.tpm, k.handle.Handle)
	err := k.tpm.Close()
	k.tpm = nil
	return err
}

func flush(tpm transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(tpm)
}

func flushTransient(tpm transport.TPM) error {
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: uint32(tpm2.TPMHTTransient) << 24, PropertyCount: 64}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("tpm2key: list loaded objects: %w", err)
	}
	hs, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("tpm2key: list loaded objects: %w", err)
	}
	for _, h := range hs.Handle {
		flush(tpm, h)
	}
	return nil
}

// writeBlob writes the key file atomically with 0600. The blob is not a
// secret in the way a software key is (it only works inside this TPM), but
// nobody else has any business with it.
func writeBlob(path string, blob blobFile) error {
	b, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("tpm2key: mkdir: %w", err)
	}
	tmp := path + ".tmp"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("tpm2key: create: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("tpm2key: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("tpm2key: rename: %w", err)
	}
	return nil
}
