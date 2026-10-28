package node

import (
	"fmt"
	"sync"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// history is this node's binding.Guard: per node the newest binding it
// verified and the newest revocation, so that neither survives a restart as
// something the control plane could undo. What is kept is the anchors'
// (internal/anchors), which take nothing on this node's word: every entry
// goes there with the signed binding or revocation that proves it.
// The network's identity comes from the pinned admin key list.
type history struct {
	a     anchors.Anchors
	trust *trustStore

	mu      sync.Mutex
	nodes   anchors.Book
	issued  map[string]bool // nodes whose newest binding is not recorded yet
	revoked map[string]bool // the same for revocations
}

func loadHistory(a anchors.Anchors, trust *trustStore) (*history, error) {
	book, err := a.History()
	if err != nil {
		return nil, err
	}
	return &history{a: a, trust: trust, nodes: book, issued: map[string]bool{}, revoked: map[string]bool{}}, nil
}

func (h *history) Deployment() string { return h.trust.current().Genesis }

func (h *history) Check(b binding.Binding) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nodes.Check(b)
}

func (h *history) Saw(b binding.Binding) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nodes.Saw(b.NodeID, b.Issued) {
		h.issued[b.NodeID] = true
	}
}

func (h *history) Revoke(r binding.Revocation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nodes.Revoke(r.NodeID, r.Issued) {
		h.revoked[r.NodeID] = true
	}
}

// evidenceBytes bounds one Record: under privilege separation it is one
// message to the parent.
const evidenceBytes = 32 << 10

// save records what changed, with its proof from s, the snapshot that was
// just verified. What is not recorded would be forgotten by a restart, so a
// snapshot is only used after this succeeded.
func (h *history) save(s *registry.Snapshot) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.issued) == 0 && len(h.revoked) == 0 {
		return nil
	}
	// what is recorded stays pending until the anchors have it: a write
	// that failed is tried again with the next look at a snapshot. Taken
	// off before, it was forgotten -- the book in memory had moved on, so
	// the retry saw nothing new and used the snapshot with the history on
	// disk behind it, and a restart would take the older binding again.
	type item struct {
		ev       anchors.Evidence
		node     string
		revoking bool
	}
	var items []item
	issued, revoked := map[string]bool{}, map[string]bool{}
	bindingOf := func(n registry.Node) {
		if h.issued[string(n.ID)] && n.Binding != "" {
			if b, err := binding.Parse([]byte(n.Binding)); err == nil && b.Issued == h.nodes[b.NodeID].Issued {
				items = append(items, item{ev: anchors.Evidence{Binding: n.Binding, Signature: n.Signature}, node: string(n.ID)})
				issued[string(n.ID)] = true
			}
		}
	}
	bindingOf(s.Self)
	for _, p := range s.Peers {
		bindingOf(p)
	}
	for _, sr := range s.Revocations {
		if r, err := binding.ParseRevocation([]byte(sr.Revocation)); err == nil && h.revoked[r.NodeID] && r.Issued == h.nodes[r.NodeID].Revoked {
			items = append(items, item{ev: anchors.Evidence{Revocation: sr.Revocation, Signature: sr.Signature}, node: r.NodeID, revoking: true})
			revoked[r.NodeID] = true
		}
	}
	if len(issued) != len(h.issued) || len(revoked) != len(h.revoked) {
		// a change without its proof in the snapshot that brought it
		n := len(h.issued) - len(issued) + len(h.revoked) - len(revoked)
		h.issued, h.revoked = map[string]bool{}, map[string]bool{}
		return fmt.Errorf("store binding history: %d changes have no signed record in the snapshot", n)
	}
	for len(items) > 0 {
		n, size := 0, 0
		for n < len(items) && n < anchors.MaxEvidence {
			e := items[n].ev
			size += len(e.Binding) + len(e.Revocation) + len(e.Signature) + 64
			if n > 0 && size > evidenceBytes {
				break
			}
			n++
		}
		ev := make([]anchors.Evidence, n)
		for i := range ev {
			ev[i] = items[i].ev
		}
		if err := h.a.Record(ev); err != nil {
			return fmt.Errorf("store binding history: %w", err)
		}
		for _, it := range items[:n] {
			if it.revoking {
				delete(h.revoked, it.node)
			} else {
				delete(h.issued, it.node)
			}
		}
		items = items[n:]
	}
	return nil
}
