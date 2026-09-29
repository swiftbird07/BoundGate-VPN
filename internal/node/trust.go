package node

import (
	"sync"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

// trustStore holds the admin key list this node accepts. The list itself
// and the rule by which it moves are the anchors' (internal/anchors: pinned
// on first contact or checked against a provisioned genesis hash, then only
// along links signed by a key of the current list, and on disk before it
// is used); this is the node's copy of the outcome.
type trustStore struct {
	a anchors.Anchors

	mu  sync.Mutex
	cur binding.Trust
}

// loadTrust reads the stored trust. Nothing stored means nothing is pinned
// yet; what is stored and unreadable is an error, never a reason to pin
// again.
func loadTrust(a anchors.Anchors) (*trustStore, error) {
	cur, err := a.Trust()
	if err != nil {
		return nil, err
	}
	return &trustStore{a: a, cur: cur}, nil
}

func (ts *trustStore) current() binding.Trust {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.cur
}

func (ts *trustStore) signers() binding.Signers {
	s, _ := ts.current().Signers()
	return s
}

// apply has the anchors verify chain and adopts the result. It reports
// whether trust moved and whether this was the first pin.
func (ts *trustStore) apply(chain []binding.SignedSet) (moved, first bool, err error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	next, err := ts.a.Follow(chain)
	if err != nil {
		return false, false, err
	}
	first = !ts.cur.Pinned() && next.Pinned()
	moved = next.Hash != ts.cur.Hash // else at most the network's identity was learned
	ts.cur = next
	return moved, first, nil
}
