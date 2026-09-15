// Package transport is the security core of BoundGate: it terminates mTLS
// over QUIC, verifies the device key against the registry, and carries IP
// packets with CONNECT-IP (RFC 9484).
//
// Trust boundary: only this package can construct an AuthenticatedPeer. Every
// layer above (sessions, ACL, forwarding) receives one and can only narrow
// what it grants. There is no API to mark a peer as authenticated by any
// other means. See docs/TCB.md.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// DeviceID identifies an enrolled device in the registry.
type DeviceID string

// DeviceInfo is what the registry knows about an approved device key.
type DeviceInfo struct {
	ID            DeviceID
	HardwareBound bool
}

// DeviceLookup answers "is this key an approved device?". It must only return
// approved devices; pending and revoked devices are unknown to it. It is
// consulted on every TLS handshake and again when a tunnel is requested.
type DeviceLookup interface {
	LookupSPKI(h devicekey.SPKIHash) (DeviceInfo, bool)
}

// AuthenticatedPeer is a device whose key was proven in the TLS handshake and
// found in the registry. Fields are unexported on purpose: the only
// constructor is PeerFromTLSState in this package.
type AuthenticatedPeer struct {
	deviceID      DeviceID
	spki          devicekey.SPKIHash
	sourceIP      netip.Addr
	hardwareBound bool
}

// DeviceID returns the registry ID of the device.
func (p AuthenticatedPeer) DeviceID() DeviceID { return p.deviceID }

// SPKI returns the hash of the proven public key.
func (p AuthenticatedPeer) SPKI() devicekey.SPKIHash { return p.spki }

// SourceIP is the observed transport source address. It is a signal for
// logging and policy, never an authentication factor.
func (p AuthenticatedPeer) SourceIP() netip.Addr { return p.sourceIP }

// HardwareBound reports what the registry recorded at enrollment.
func (p AuthenticatedPeer) HardwareBound() bool { return p.hardwareBound }

// IsZero reports whether p is the zero value (never authenticated).
func (p AuthenticatedPeer) IsZero() bool { return p.deviceID == "" }

// String is safe for logs.
func (p AuthenticatedPeer) String() string {
	return fmt.Sprintf("device=%s spki=%s src=%s", p.deviceID, p.spki, p.sourceIP)
}

// LogValue implements slog.LogValuer so structured logs show the peer even
// though its fields are unexported.
func (p AuthenticatedPeer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("device", string(p.deviceID)),
		slog.String("spki", p.spki.String()),
		slog.String("src", p.sourceIP.String()),
		slog.Bool("hardware_bound", p.hardwareBound),
	)
}

// Errors returned by the verifiers. They are deliberately generic towards the
// peer; details go to the server log only.
var (
	ErrNoClientCert     = errors.New("transport: no client certificate")
	ErrBadClientCert    = errors.New("transport: client certificate rejected")
	ErrUnknownDevice    = errors.New("transport: device key not approved")
	ErrNotAuthenticated = errors.New("transport: connection has no authenticated peer")
)

// parseDeviceCert enforces the structural rules for a device certificate:
// exactly one certificate, ECDSA P-256, self-signed with a valid signature,
// currently valid. It returns the SPKI hash of the key.
//
// The self-signature check matters even though we do not use a CA: it proves
// the certificate was produced by the holder of the key rather than being an
// arbitrary blob wrapped around a public key, and the TLS handshake proves
// possession of that key.
func parseDeviceCert(rawCerts [][]byte, now time.Time) (*x509.Certificate, devicekey.SPKIHash, error) {
	if len(rawCerts) == 0 {
		return nil, devicekey.SPKIHash{}, ErrNoClientCert
	}
	if len(rawCerts) != 1 {
		return nil, devicekey.SPKIHash{}, fmt.Errorf("%w: expected exactly one certificate, got %d", ErrBadClientCert, len(rawCerts))
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, devicekey.SPKIHash{}, fmt.Errorf("%w: %v", ErrBadClientCert, err)
	}
	if err := devicekey.CheckPublicKey(cert.PublicKey); err != nil {
		return nil, devicekey.SPKIHash{}, fmt.Errorf("%w: %v", ErrBadClientCert, err)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, devicekey.SPKIHash{}, fmt.Errorf("%w: not self-signed: %v", ErrBadClientCert, err)
	}
	if cert.IsCA {
		return nil, devicekey.SPKIHash{}, fmt.Errorf("%w: CA certificates are not device certificates", ErrBadClientCert)
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, devicekey.SPKIHash{}, fmt.Errorf("%w: outside validity period", ErrBadClientCert)
	}
	h, err := devicekey.HashPublicKey(cert.PublicKey)
	if err != nil {
		return nil, devicekey.SPKIHash{}, fmt.Errorf("%w: %v", ErrBadClientCert, err)
	}
	return cert, h, nil
}

// verifyDevice is the handshake-time check used by ServerTLSConfig. A lookup
// miss fails the TLS handshake, so no HTTP/3 layer ever exists for an
// unapproved device.
func verifyDevice(lookup DeviceLookup, rawCerts [][]byte) error {
	_, h, err := parseDeviceCert(rawCerts, time.Now())
	if err != nil {
		return err
	}
	if lookup == nil {
		return nil
	}
	if _, ok := lookup.LookupSPKI(h); !ok {
		return ErrUnknownDevice
	}
	return nil
}

// PeerFromTLSState builds the AuthenticatedPeer for an established
// connection. It repeats the certificate checks and the registry lookup so
// that a device revoked between handshake and request is rejected here too.
func PeerFromTLSState(st *tls.ConnectionState, lookup DeviceLookup, src netip.Addr) (AuthenticatedPeer, error) {
	if st == nil || !st.HandshakeComplete {
		return AuthenticatedPeer{}, ErrNotAuthenticated
	}
	if st.Version < tls.VersionTLS13 {
		return AuthenticatedPeer{}, fmt.Errorf("%w: TLS version too old", ErrBadClientCert)
	}
	raw := make([][]byte, 0, len(st.PeerCertificates))
	for _, c := range st.PeerCertificates {
		raw = append(raw, c.Raw)
	}
	_, h, err := parseDeviceCert(raw, time.Now())
	if err != nil {
		return AuthenticatedPeer{}, err
	}
	if lookup == nil {
		return AuthenticatedPeer{}, ErrNotAuthenticated
	}
	info, ok := lookup.LookupSPKI(h)
	if !ok {
		return AuthenticatedPeer{}, ErrUnknownDevice
	}
	return AuthenticatedPeer{
		deviceID:      info.ID,
		spki:          h,
		sourceIP:      src,
		hardwareBound: info.HardwareBound,
	}, nil
}

// UnverifiedSPKI returns the SPKI hash of a structurally valid device
// certificate without consulting the registry. It exists for exactly one
// caller: the enrollment endpoint, which records a pending device. The
// result must never be treated as an authenticated identity.
func UnverifiedSPKI(st *tls.ConnectionState) (devicekey.SPKIHash, error) {
	if st == nil || !st.HandshakeComplete {
		return devicekey.SPKIHash{}, ErrNotAuthenticated
	}
	raw := make([][]byte, 0, len(st.PeerCertificates))
	for _, c := range st.PeerCertificates {
		raw = append(raw, c.Raw)
	}
	_, h, err := parseDeviceCert(raw, time.Now())
	return h, err
}
