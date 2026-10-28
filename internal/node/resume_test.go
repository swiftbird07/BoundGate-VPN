package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/profile"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// resumeNode is a node whose Up gets as far as the bypass route to the
// control plane and fails there, for lack of a resolver: enough to see that
// an up was attempted (Status.LastError) without a TUN.
func resumeNode() *Node {
	log := slog.New(slog.DiscardHandler)
	n := &Node{log: log, cfg: Config{Profile: "full", ControlAddr: "control.test:443", AllowOverlap: true},
		holder: &registry.Holder{}, control: testControl(),
		hosts: &hosts{known: map[string][]netip.Addr{}, stale: map[string]bool{}, good: map[string]netip.Addr{}, log: log,
			lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return nil, errors.New("no resolver in this test")
			}}}
	n.status.Enrollment = "approved"
	snap := loopSnapshot()
	snap.Self = registry.Node{ID: "laptop", OverlayIP: netip.MustParseAddr("10.25.0.3")}
	n.holder.Store(snap)
	return n
}

// upAttempted waits for the auto up to have run into the missing resolver.
func upAttempted(t *testing.T, n *Node) bool {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if n.Status().LastError != "" {
			return true
		}
	}
	return false
}

// The overlay went down because its snapshot ran out (staleWatch), and the
// control plane answers while the old session is still being torn down: the
// snapshot arrives before watch has cleared the session. onSnapshot cannot
// bring the overlay back then; watch does, once the session is gone.
func TestResumeWhenTheSnapshotArrivesDuringTheTeardown(t *testing.T) {
	n := resumeNode()
	old := &session{n: n, done: make(chan struct{}), profile: profile.Full(), flows: flow.New(flow.Timeouts{}, nil), reason: "the registry snapshot ran out"}
	n.sess = old
	n.resume = "full" // what staleWatch leaves behind
	n.onSnapshot(registry.Diff{}, n.holder.Load())
	n.mu.Lock()
	sess, resume := n.sess, n.resume
	n.mu.Unlock()
	if sess != old || resume != "full" {
		t.Fatalf("with the old session still there: sess=%v resume=%q", sess == old, resume)
	}
	if n.Status().LastError != "" {
		t.Fatalf("an up was attempted over the old session: %q", n.Status().LastError)
	}

	close(old.done)
	n.watch(old)
	n.mu.Lock()
	resume = n.resume
	n.mu.Unlock()
	if resume != "" {
		t.Errorf("the resume is still pending after the session ended: %q", resume)
	}
	if !upAttempted(t, n) {
		t.Fatal("the overlay was not brought back once the old session was gone")
	}
}

// The usual order: the old session is gone first, the snapshot brings the
// overlay back.
func TestResumeWithTheNextSnapshot(t *testing.T) {
	n := resumeNode()
	n.resume = "full"
	n.onSnapshot(registry.Diff{}, n.holder.Load())
	if !upAttempted(t, n) {
		t.Fatal("the snapshot did not bring the overlay back")
	}
	n.mu.Lock()
	resume := n.resume
	n.mu.Unlock()
	if resume != "" {
		t.Errorf("resume still pending: %q", resume)
	}
}

// A down by the user while the overlay waits to come back cancels that.
func TestDownCancelsAPendingResume(t *testing.T) {
	n := resumeNode()
	n.resume = "full"
	n.Down("down by user")
	n.onSnapshot(registry.Diff{}, n.holder.Load())
	time.Sleep(50 * time.Millisecond)
	if n.Status().LastError != "" {
		t.Fatalf("the overlay came back after a down: %q", n.Status().LastError)
	}
}
