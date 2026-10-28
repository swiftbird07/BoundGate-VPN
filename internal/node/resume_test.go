package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
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
	n.DownByUser()
	n.onSnapshot(registry.Diff{}, n.holder.Load())
	time.Sleep(50 * time.Millisecond)
	if n.Status().LastError != "" {
		t.Fatalf("the overlay came back after a down: %q", n.Status().LastError)
	}
}

// An app learns from the status that the overlay comes back by itself, and
// keeps its VPN service for it; after a down by the user it does not.
func TestTheStatusSaysTheOverlayComesBack(t *testing.T) {
	n := resumeNode()
	n.resume = "full"
	if !n.Status().Resuming {
		t.Fatal("a pending resume is not in the status")
	}
	n.DownByUser()
	if n.Status().Resuming {
		t.Fatal("after a down by the user nothing comes back")
	}
}

// Status changes reach the app in the order they happened: each is handed
// over from a goroutine of its own, and an app that was told the newer one
// must not be told the older one after it (a "sign-in needed" after the
// "connected" that followed it stayed on the screen for hours).
func TestStatusChangesArriveInOrder(t *testing.T) {
	for range 50 {
		n := resumeNode()
		var mu sync.Mutex
		var got []string
		n.cfg.OnStatus = func(s Status) {
			mu.Lock()
			got = append(got, s.Profile)
			mu.Unlock()
		}
		n.notify.Lock() // the app is busy: the changes queue up behind it
		for _, p := range []string{"a", "b", "c", "d"} {
			n.mu.Lock()
			n.status.Profile = p
			n.mu.Unlock()
			n.publishStatus()
		}
		n.notify.Unlock()
		deadline := time.Now().Add(2 * time.Second)
		for {
			mu.Lock()
			last := ""
			if len(got) > 0 {
				last = got[len(got)-1]
			}
			sorted := slices.IsSorted(got)
			mu.Unlock()
			if !sorted {
				t.Fatalf("delivered out of order: %v", got)
			}
			if last == "d" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the newest status never arrived: %v", got)
			}
			time.Sleep(time.Millisecond)
		}
	}
}

// While Up is still applying a session, the status says so: the spoke and
// the server exist before the overlay is up (an app showed "connected",
// without an overlay address, for an up that then failed).
func TestTheStatusStaysStartingWhileUpApplies(t *testing.T) {
	n := resumeNode()
	s := &session{n: n, done: make(chan struct{}), profile: profile.Full(), flows: flow.New(flow.Timeouts{}, nil)}
	s.spoke = newSpokeManager(s)
	n.sess = s
	n.status.State = StateStarting
	if st := n.Status().State; st != StateStarting {
		t.Fatalf("state %q while the session is still being applied", st)
	}
}
