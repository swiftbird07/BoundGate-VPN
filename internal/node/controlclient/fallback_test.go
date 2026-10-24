package controlclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
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

// After a request that failed, the next dial goes to the address the
// control plane answered at before, when its name now resolves to another
// one (R140: a hub's resolver answers the name while the overlay is up);
// after one that failed too, to the resolved one again. A success confirms
// the address that answered.
func TestAFailedRequestTriesTheAddressThatAnsweredBefore(t *testing.T) {
	fresh, good := netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("203.0.113.7")
	var confirmed []netip.Addr
	d := &dualTransport{log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolve:  func(context.Context, string) (netip.Addr, error) { return fresh, nil },
		confirm:  func(_ string, a netip.Addr) { confirmed = append(confirmed, a) },
		lastGood: func(_ string, tried netip.Addr) (netip.Addr, bool) { return good, tried != good }}
	ctx := context.Background()
	dial := func() netip.Addr {
		ap, err := d.addr(ctx, "vpn.example:443")
		if err != nil {
			t.Fatal(err)
		}
		return ap.Addr()
	}
	if a := dial(); a != fresh {
		t.Fatalf("the first dial goes to what the name resolves to, not %v", a)
	}
	d.answered(false)
	if a := dial(); a != good {
		t.Fatalf("after a failure the dial goes to the address that answered before, not %v", a)
	}
	d.answered(false)
	if a := dial(); a != fresh {
		t.Fatalf("after a second failure the resolved address again, not %v", a)
	}
	d.answered(true)
	if a := dial(); a != fresh {
		t.Fatalf("after a success the resolved address, not %v", a)
	}
	d.answered(false)
	dial()
	d.answered(true)
	if len(confirmed) != 2 || confirmed[0] != fresh || confirmed[1] != good {
		t.Fatalf("confirmed: %v", confirmed)
	}
}
