package node

import (
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// A network change redials hubs that failed, but not those that refused this
// device: asking again changes nothing until the control plane says
// something else, and doing it on every change (a phone's network changes
// often) cost a handshake each time. A sign-in or a new snapshot pokes those
// too — it is what a hub older than this node, which still asks for a user
// session, waits for.
func TestRetryNowLeavesARefusalAlone(t *testing.T) {
	failed := &hubLink{state: "error", retry: make(chan bool, 1)}
	refused := &hubLink{state: "refused", retry: make(chan bool, 1)}
	old := &hubLink{state: "login required", retry: make(chan bool, 1)}
	m := &spokeManager{links: map[transport.DeviceID]*hubLink{"a": failed, "b": refused, "c": old}}

	m.retryNow(false)
	if len(failed.retry) != 1 || len(refused.retry) != 0 || len(old.retry) != 0 {
		t.Fatalf("network change: failed poked %d, refused %d, login required %d",
			len(failed.retry), len(refused.retry), len(old.retry))
	}
	<-failed.retry

	m.retryNow(true)
	for name, l := range map[string]*hubLink{"refused": refused, "login required": old, "failed": failed} {
		if s := <-l.retry; !s {
			t.Fatalf("the sign-in poke does not reach the %s link", name)
		}
	}
}
