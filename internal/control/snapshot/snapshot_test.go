package snapshot

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
)

// A change that commits between a long-poll's look at the version and its
// joining the waiters wakes nobody; the poll must still see it at once
// instead of sleeping out its whole timeout.
func TestWaitSeesAVersionNotifiedWhileJoining(t *testing.T) {
	store, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := New(store)
	cur, _ := store.SnapshotVersion(context.Background())
	// the notification of a version the database read above did not show
	// yet (it committed in between)
	s.Notify(cur + 1)
	start := time.Now()
	newer, err := s.Wait(context.Background(), cur, 5*time.Second)
	if err != nil || !newer {
		t.Fatalf("newer=%v err=%v", newer, err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("the poll slept %s although a newer version was announced", time.Since(start).Round(time.Millisecond))
	}
	// nothing newer: the poll waits
	start = time.Now()
	if newer, _ := s.Wait(context.Background(), cur+1, 100*time.Millisecond); newer || time.Since(start) < 100*time.Millisecond {
		t.Fatalf("newer=%v after %s", newer, time.Since(start))
	}
}

// A node ahead of the control plane (restored from a backup) is answered at
// once, with the snapshot as it is here: "not modified" told it that what it
// has is current, so its snapshot never aged out.
func TestANodeAheadOfTheControlPlaneIsAnswered(t *testing.T) {
	store, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := New(store)
	cur, _ := store.SnapshotVersion(context.Background())
	start := time.Now()
	newer, err := s.Wait(context.Background(), cur+10, 5*time.Second)
	if err != nil || !newer || time.Since(start) > time.Second {
		t.Fatalf("newer=%v err=%v after %s", newer, err, time.Since(start))
	}
}
