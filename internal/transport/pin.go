package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/quic-go/quic-go/http3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// HubServerName is the TLS server name (SNI) and URI host used for every
// hub tunnel listener. Hubs are not identified by name but by the pinned
// SPKI of their device key, so one constant serves all of them.
const HubServerName = "hub.boundgate"

// HubTemplate is the CONNECT-IP URI template every hub serves.
const HubTemplate = "https://" + HubServerName + "/vpn"

// ErrHubKeyMismatch is returned when a hub presents a key other than the one
// the registry announced for it.
var ErrHubKeyMismatch = fmt.Errorf("%w: hub key does not match the registry", ErrBadClientCert)

// ClientTLSConfigPinned returns the spoke-side configuration for dialing a
// hub: present the device certificate and accept the hub only if it proves
// possession of the key whose SPKI hash the registry announced. No CA and no
// hostname are involved; the hub's certificate is its own device certificate.
func ClientTLSConfigPinned(device tls.Certificate, expected devicekey.SPKIHash) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{device},
		ServerName:             HubServerName,
		NextProtos:             []string{http3.NextProtoH3},
		SessionTicketsDisabled: true,
		// Verification happens in VerifyPeerCertificate below; the standard
		// chain/hostname check cannot express "this exact key".
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinned(expected, rawCerts)
		},
	}
}

// verifyPinned applies the device-certificate rules to the server's
// certificate and compares its key with the expected one.
func verifyPinned(expected devicekey.SPKIHash, rawCerts [][]byte) error {
	if expected.IsZero() {
		return fmt.Errorf("%w: no expected key", ErrHubKeyMismatch)
	}
	_, h, err := parseDeviceCert(rawCerts, time.Now())
	if err != nil {
		return err
	}
	if h != expected {
		return ErrHubKeyMismatch
	}
	return nil
}
