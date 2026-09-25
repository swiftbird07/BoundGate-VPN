package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

// maxHistory bounds the nodes remembered; above it the oldest entries that
// are not revocations are forgotten first.
const maxHistory = 20000

// history is this node's binding.Guard: per node the newest binding it
// verified and the newest revocation, kept in the state directory so that
// neither survives a restart as something the control plane could undo.
// The network's identity comes from the pinned admin key list.
type history struct {
	path  string
	trust *trustStore

	mu    sync.Mutex
	nodes map[string]historyEntry
	dirty bool
}

type historyEntry struct {
	Issued  int64 `json:"issued,omitempty"`  // newest binding seen
	Revoked int64 `json:"revoked,omitempty"` // newest revocation verified
}

func loadHistory(stateDir string, trust *trustStore) (*history, error) {
	h := &history{path: filepath.Join(stateDir, "bindings_seen.json"), trust: trust, nodes: map[string]historyEntry{}}
	raw, err := os.ReadFile(h.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return h, nil
	case err != nil:
		return nil, fmt.Errorf("node: binding history: %w", err)
	}
	if err := json.Unmarshal(raw, &h.nodes); err != nil {
		// refusing to start would let a damaged file lock the node out; an
		// empty history only forgets what the node could refuse, and says so
		return nil, fmt.Errorf("node: %s is damaged (%v); restore it, or remove it to start with an empty history (older bindings a control plane still holds would then be accepted again)", h.path, err)
	}
	return h, nil
}

func (h *history) Deployment() string { return h.trust.current().Genesis }

func (h *history) Check(b binding.Binding) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.nodes[b.NodeID]
	switch {
	case e.Revoked != 0 && b.Issued <= e.Revoked:
		return binding.ErrRevoked
	case b.Issued < e.Issued:
		return binding.ErrRolledBack
	}
	return nil
}

func (h *history) Saw(b binding.Binding) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.nodes[b.NodeID]
	if b.Issued > e.Issued {
		e.Issued = b.Issued
		h.set(b.NodeID, e)
	}
}

func (h *history) Revoke(r binding.Revocation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.nodes[r.NodeID]
	if r.Issued > e.Revoked {
		e.Revoked = r.Issued
		h.set(r.NodeID, e)
	}
}

// set stores e; h.mu is held.
func (h *history) set(id string, e historyEntry) {
	if _, ok := h.nodes[id]; !ok && len(h.nodes) >= maxHistory {
		h.evict()
	}
	h.nodes[id] = e
	h.dirty = true
}

// evict drops the entry with the oldest binding that is no revocation.
func (h *history) evict() {
	var oldest string
	for id, e := range h.nodes {
		if e.Revoked != 0 {
			continue
		}
		if oldest == "" || e.Issued < h.nodes[oldest].Issued {
			oldest = id
		}
	}
	if oldest != "" {
		delete(h.nodes, oldest)
	}
}

// save writes the history if it changed. What is not on disk would be
// forgotten by a restart, so a snapshot is only used after this succeeded.
func (h *history) save() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty {
		return nil
	}
	if err := writeFileAtomic(h.path, h.nodes); err != nil {
		return fmt.Errorf("store binding history: %w", err)
	}
	h.dirty = false
	return nil
}
