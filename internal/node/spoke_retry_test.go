package node

import (
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// A network change redials hubs that failed, but not those that refused us
// for lack of a user session: asking again changes nothing before the
// sign-in, and doing it on every change (a phone's network changes often)
// cost a handshake each time. The sign-in pokes those too.
func TestRetryNowWaitsForTheSession(t *testing.T) {
	failed := &hubLink{state: "error", retry: make(chan bool, 1)}
	refused := &hubLink{state: "login required", retry: make(chan bool, 1)}
	m := &spokeManager{links: map[transport.DeviceID]*hubLink{"a": failed, "b": refused}}

	m.retryNow(false)
	if len(failed.retry) != 1 || len(refused.retry) != 0 {
		t.Fatalf("network change: failed poked %d, refused poked %d", len(failed.retry), len(refused.retry))
	}
	<-failed.retry

	m.retryNow(true)
	if s := <-refused.retry; !s {
		t.Fatal("the sign-in poke does not say the session changed")
	}
	if s := <-failed.retry; !s {
		t.Fatal("the sign-in poke does not reach every waiting link")
	}
}
