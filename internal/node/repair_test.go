package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

// sweepNet is a host whose resolver can be given back, and which remembers
// what was asked of it. One entry belongs to a device that is gone, one to a
// node that is running.
type sweepNet struct {
	netcfg.Configurator
	mu    sync.Mutex
	calls []string
	dead  []string
	live  []string
	err   error
}

func (s *sweepNet) SetLinkDNS(_ context.Context, ifname string, servers []netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(servers) == 0 {
		s.calls = append(s.calls, "dns off "+ifname)
	} else {
		s.calls = append(s.calls, "dns on "+ifname)
	}
	return nil
}

func (s *sweepNet) SweepDNS(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "sweep")
	return s.dead, s.err
}

func (s *sweepNet) LiveDNSKeys(context.Context) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live
}

// A repair gives back a resolver entry whose device is gone, says so in one
// sentence, and leaves the entry of a node that is still running alone --
// taking that one away would break the machine the repair is here to fix.
func TestARepairGivesTheResolverBackAndLeavesARunningNodeAlone(t *testing.T) {
	net := &sweepNet{
		dead: []string{"State:/Network/Service/boundgate-utun9/DNS"},
		live: []string{"State:/Network/Service/boundgate-utun4/DNS"},
	}
	n := &Node{net: net, log: slog.New(slog.DiscardHandler)}
	rep, err := n.Repair(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 || rep.Removed[0] != net.dead[0] {
		t.Errorf("removed %v", rep.Removed)
	}
	if len(rep.LeftAlone) != 1 || rep.LeftAlone[0] != net.live[0] {
		t.Errorf("left alone %v", rep.LeftAlone)
	}
	if rep.Reapplied {
		t.Error("routes were applied again although no session is up")
	}
	if !strings.Contains(rep.Summary, "resolver back") {
		t.Errorf("summary %q", rep.Summary)
	}
}

// A host that carries nothing says so, and the summary does not pretend that
// an entry of a running node was something to repair.
func TestARepairWithNothingToDoSaysSo(t *testing.T) {
	n := &Node{net: &sweepNet{}, log: slog.New(slog.DiscardHandler)}
	rep, err := n.Repair(context.Background())
	if err != nil || !strings.HasPrefix(rep.Summary, "Nothing to repair") {
		t.Fatalf("%q %v", rep.Summary, err)
	}
	n = &Node{net: &sweepNet{live: []string{"State:/Network/Service/boundgate-utun4/DNS"}},
		log: slog.New(slog.DiscardHandler)}
	rep, _ = n.Repair(context.Background())
	if !strings.Contains(rep.Summary, "belongs to a node that is running") {
		t.Errorf("summary %q", rep.Summary)
	}
}

// A sweep that fails is an error, not a quiet "nothing to do": the one thing
// this is for is a host that cannot resolve a name (R144).
func TestARepairThatCouldNotGiveTheResolverBackSaysSo(t *testing.T) {
	net := &sweepNet{err: errors.New("scutil: no answer")}
	n := &Node{net: net, log: slog.New(slog.DiscardHandler)}
	if _, err := n.Repair(context.Background()); err == nil {
		t.Fatal("a failed sweep was reported as success")
	}
}

// What a run that is gone recorded is undone, with no node of its own: the
// journal of the dead run, replayed by the daemon-less repair.
func TestARepairUndoesWhatTheJournalRecorded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netstate.json")
	first := &sweepNet{}
	j := netcfg.NewJournal(first, path)
	if err := j.SetLinkDNS(context.Background(), "utun9", []netip.Addr{netip.MustParseAddr("10.60.0.53")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the journal kept no record: %v", err)
	}
	// the next run, on the same host: the record is all it has
	second := &sweepNet{}
	rep, err := RepairHost(context.Background(), netcfg.NewJournal(second, path))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Undone != 1 {
		t.Errorf("undone %d", rep.Undone)
	}
	if len(second.calls) == 0 || second.calls[0] != "dns off utun9" {
		t.Errorf("calls %v", second.calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the journal is still there after everything was undone: %v", err)
	}
}
