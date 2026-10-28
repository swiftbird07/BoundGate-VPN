package node

import (
	"errors"
	"net/netip"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// flakyAnchors fails its first Record and keeps what later ones bring.
type flakyAnchors struct {
	anchors.Anchors
	fails    int
	recorded []anchors.Evidence
}

func (f *flakyAnchors) Record(ev []anchors.Evidence) error {
	if f.fails > 0 {
		f.fails--
		return errors.New("disk full")
	}
	f.recorded = append(f.recorded, ev...)
	return nil
}

// A binding whose record could not be written stays pending: the next look
// at the snapshot writes it. Forgotten, the snapshot was used on the retry
// with the history on disk behind it, and a restart would accept the older
// binding the history exists to refuse.
func TestAHistoryWriteThatFailedIsTriedAgain(t *testing.T) {
	a := &flakyAnchors{fails: 1}
	h := &history{a: a, nodes: anchors.Book{}, issued: map[string]bool{}, revoked: map[string]bool{}}
	peer := registry.Node{ID: "nas", SPKI: [32]byte{1}, KeyVersion: 1, Kind: registry.KindWorkload, Roles: []registry.Role{registry.RoleEndpoint}, OverlayIP: netip.MustParseAddr("10.25.0.9")}
	b := binding.FromNode(peer)
	b.Issued = 2000
	raw, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	peer.Binding, peer.Signature = string(raw), "sig"
	snap := &registry.Snapshot{Peers: []registry.Node{peer}}

	h.Saw(b)
	if err := h.save(snap); err == nil {
		t.Fatal("the failed write must refuse the snapshot")
	}
	// the retry of the same snapshot: the book in memory has it already
	h.Saw(b)
	if err := h.save(snap); err != nil {
		t.Fatal(err)
	}
	if len(a.recorded) != 1 || a.recorded[0].Binding != string(raw) {
		t.Fatalf("recorded %v: the binding never reached the history", a.recorded)
	}
}
