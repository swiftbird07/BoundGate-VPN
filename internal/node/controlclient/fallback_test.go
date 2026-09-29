package controlclient

import (
	"errors"
	"fmt"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Only a path without UDP answers sends the control channel to TCP. A
// handshake that failed on its content (the pin a node has not accepted yet
// while it enrolls) would fail over TCP the same way.
func TestAnsweredOverUDP(t *testing.T) {
	pin := fmt.Errorf("dial: %w", &quic.TransportError{ErrorCode: 0x12a, ErrorMessage: "pin control plane key"})
	if !answeredOverUDP(pin) {
		t.Fatal("a refused pin is not a reason for TCP")
	}
	// a connection this node closed itself under a request (reset after a
	// change of network): HTTP/3 ended it, no path dropped anything
	if !answeredOverUDP(fmt.Errorf("round trip: %w", &http3.Error{ErrorCode: 0})) {
		t.Fatal("a connection closed as HTTP/3 counts as no answer over UDP")
	}
	if !answeredOverUDP(&quic.ApplicationError{ErrorCode: 0x100}) {
		t.Fatal("a connection closed by the server is not a reason for TCP")
	}
	for _, e := range []error{&quic.HandshakeTimeoutError{}, &quic.IdleTimeoutError{}, errors.New("sendmsg: network is unreachable")} {
		if answeredOverUDP(e) {
			t.Fatalf("%v: no answer over UDP, TCP must be tried", e)
		}
	}
}
