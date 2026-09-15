package transport

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/quic-go/quic-go/http3"
)

// ServerTLSConfig returns the TLS configuration for a listener that only
// admits approved devices. The registry lookup runs inside the handshake:
// an unknown key means the handshake fails and nothing above TLS is reached.
//
// Client certificates are not chain-validated (there is no CA); they are
// validated structurally by parseDeviceCert and by registry membership.
func ServerTLSConfig(serverCert tls.Certificate, lookup DeviceLookup) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyDevice(lookup, rawCerts)
		},
		NextProtos: []string{http3.NextProtoH3},
	}
}

// ServerTLSConfigAnyDevice admits any structurally valid device certificate
// without a registry lookup. It is for the control plane's enrollment
// listener only, where the point is to learn a new key. Handlers behind it
// must use UnverifiedSPKI and must not grant anything.
func ServerTLSConfigAnyDevice(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyDevice(nil, rawCerts)
		},
	}
}

// ClientTLSConfig returns the agent-side configuration: present the device
// certificate, trust only the given roots for the server, TLS 1.3 only.
// Session resumption and 0-RTT stay disabled so every connection performs a
// full handshake with a fresh proof of key possession.
func ClientTLSConfig(device tls.Certificate, roots *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{device},
		RootCAs:                roots,
		ServerName:             serverName,
		NextProtos:             []string{http3.NextProtoH3},
		SessionTicketsDisabled: true,
	}
}
