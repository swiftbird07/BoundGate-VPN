package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// The node channel to the control plane is not WebPKI: nodes pin the SPKI
// hash of the control plane's long-lived node-channel key, the way SSH pins
// host keys. The first connection learns the key (trust on first use, the
// fingerprint is logged and shown by the CLI) unless a pin was provisioned
// by configuration. A different key afterwards is refused until an operator
// re-pins deliberately.

// ErrControlKeyMismatch is returned when the control plane presents a key
// other than the pinned one.
var ErrControlKeyMismatch = errors.New("transport: control plane key does not match the pinned key")

// PinStore persists the control plane pin.
type PinStore interface {
	// Pinned returns the pinned key hash, if any.
	Pinned() (devicekey.SPKIHash, bool)
	// Learn stores the key seen on first use.
	Learn(h devicekey.SPKIHash) error
}

// MemPin is a PinStore in memory (tests, or a pin fixed by configuration).
type MemPin struct {
	mu sync.Mutex
	h  devicekey.SPKIHash
	ok bool
}

// NewMemPin returns a store; a zero hash means "learn on first use".
func NewMemPin(h devicekey.SPKIHash) *MemPin { return &MemPin{h: h, ok: !h.IsZero()} }

// Pinned implements PinStore.
func (m *MemPin) Pinned() (devicekey.SPKIHash, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.h, m.ok
}

// Learn implements PinStore.
func (m *MemPin) Learn(h devicekey.SPKIHash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.h, m.ok = h, true
	return nil
}

// ClientTLSConfigControl returns the node-side configuration for the
// control channel: present the device certificate, use the node server
// name, and accept the server only if its key matches the pin (or learn it
// on first use). onLearn, if set, is called once when a key is pinned.
func ClientTLSConfigControl(device tls.Certificate, serverName string, pins PinStore, onLearn func(devicekey.SPKIHash)) *tls.Config {
	var learnOnce sync.Once
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{device},
		ServerName:             serverName,
		SessionTicketsDisabled: true,
		// The pin replaces chain and hostname validation.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			h, err := serverKeyHash(rawCerts)
			if err != nil {
				return err
			}
			if pinned, ok := pins.Pinned(); ok {
				if h != pinned {
					return fmt.Errorf("%w: pinned %s, presented %s", ErrControlKeyMismatch, pinned.Fingerprint(), h.Fingerprint())
				}
				return nil
			}
			if err := pins.Learn(h); err != nil {
				return fmt.Errorf("transport: pin control plane key: %w", err)
			}
			if onLearn != nil {
				learnOnce.Do(func() { onLearn(h) })
			}
			return nil
		},
	}
}

// serverKeyHash parses the control plane's leaf certificate: P-256, valid
// now, and returns the SPKI hash. No chain is built; the pin is the trust.
func serverKeyHash(rawCerts [][]byte) (devicekey.SPKIHash, error) {
	if len(rawCerts) == 0 {
		return devicekey.SPKIHash{}, errors.New("transport: control plane sent no certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return devicekey.SPKIHash{}, fmt.Errorf("transport: control plane certificate: %w", err)
	}
	if err := devicekey.CheckPublicKey(cert.PublicKey); err != nil {
		return devicekey.SPKIHash{}, fmt.Errorf("transport: control plane certificate: %w", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return devicekey.SPKIHash{}, errors.New("transport: control plane certificate outside validity period")
	}
	return devicekey.HashPublicKey(cert.PublicKey)
}
