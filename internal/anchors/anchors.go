// Package anchors keeps what a node trusts from one start to the next: the
// control plane's key it pinned, the admin key list it follows, and the
// newest binding and revocation it saw of every node. Everything else a
// node believes is derived from these three and from what the control plane
// sends; whoever can rewrite them decides whom the node takes for its
// control plane and its administrators after the next start.
//
// They therefore move only by rules that need no trust in whoever asks:
//
//   - the pin is set once, while none is set;
//   - the admin key list moves along links signed by a key of the list
//     before (binding.VerifyChain);
//   - the history takes a binding or a revocation only with its signature
//     by a key of the list, and only ever forward.
//
// Under privilege separation the privileged parent applies these rules to
// what its worker asks for (internal/privsep); a node in one process
// applies them to itself.
package anchors

import (
	"errors"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// Anchors is the node's view of them.
type Anchors interface {
	// Pin is the control plane's key; false while none is pinned. An error
	// is a pin that is there and cannot be used: never a reason to pin again.
	Pin() (devicekey.SPKIHash, bool, error)
	// SetPin pins h while nothing is pinned, and refuses otherwise.
	SetPin(h devicekey.SPKIHash) error
	// Trust is the admin key list; the zero value while none is pinned.
	Trust() (binding.Trust, error)
	// Follow verifies chain against the list and returns what is trusted
	// afterwards, which is stored before it is returned.
	Follow(chain []binding.SignedSet) (binding.Trust, error)
	// History is what was seen of every node.
	History() (Book, error)
	// Record adds to the history what the evidence proves.
	Record(ev []Evidence) error
}

// Evidence is a signed binding or a signed revocation, as the control plane
// sent it.
type Evidence struct {
	Binding    string `json:"binding,omitempty"`
	Revocation string `json:"revocation,omitempty"`
	Signature  string `json:"signature"`
}

// MaxEvidence bounds one Record.
const MaxEvidence = 256

var (
	// ErrPinned refuses a second pin.
	ErrPinned = errors.New("a control plane key is pinned already; it changes only when root removes control.pin from the state directory")
	// ErrProvisioned: the configuration names the pin.
	ErrProvisioned = errors.New("the control plane's key is set in the configuration")
	// ErrReadOnly: this view of the anchors is for reading.
	ErrReadOnly = errors.New("anchors: read-only")
)

// Entry is what is remembered of one node.
type Entry struct {
	Issued  int64 `json:"issued,omitempty"`  // newest binding seen
	Revoked int64 `json:"revoked,omitempty"` // newest revocation verified
}

// MaxHistory bounds the nodes remembered; above it the entry with the
// oldest binding that is no revocation is forgotten first.
const MaxHistory = 20000

// Book is the history: per node the newest binding and revocation.
type Book map[string]Entry

// Check refuses a binding older than one seen for the same node, or not
// newer than a revocation of it.
func (b Book) Check(x binding.Binding) error {
	e := b[x.NodeID]
	switch {
	case e.Revoked != 0 && x.Issued <= e.Revoked:
		return binding.ErrRevoked
	case x.Issued < e.Issued:
		return binding.ErrRolledBack
	}
	return nil
}

// Saw records a binding issued at issued; it reports whether that was news.
func (b Book) Saw(id string, issued int64) bool {
	e := b[id]
	if issued <= e.Issued {
		return false
	}
	e.Issued = issued
	b.set(id, e)
	return true
}

// Revoke records a revocation issued at issued; it reports whether that
// was news.
func (b Book) Revoke(id string, issued int64) bool {
	e := b[id]
	if issued <= e.Revoked {
		return false
	}
	e.Revoked = issued
	b.set(id, e)
	return true
}

func (b Book) set(id string, e Entry) {
	if _, ok := b[id]; !ok && len(b) >= MaxHistory {
		var oldest string
		for k, v := range b {
			if v.Revoked != 0 {
				continue
			}
			if oldest == "" || v.Issued < b[oldest].Issued {
				oldest = k
			}
		}
		if oldest != "" {
			delete(b, oldest)
		}
	}
	b[id] = e
}
