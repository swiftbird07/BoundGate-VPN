package node

import (
	"context"
	"fmt"
	"strings"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

// RepairReport is what a repair did, for whoever asked: the CLI prints the
// lines, the tray and the Mac app show the summary.
type RepairReport struct {
	// Undone is how many changes of a run that is gone were taken back.
	Undone int `json:"undone"`
	// Removed names the resolver entries of nodes whose device is gone.
	Removed []string `json:"removed,omitempty"`
	// LeftAlone names the entries of a node that is still running: they
	// belong to it, and taking them away would break the machine this is
	// here to repair.
	LeftAlone []string `json:"left_alone,omitempty"`
	// Reapplied says the running node's routes and resolver were applied
	// again, in case the host lost them while the node stayed up.
	Reapplied bool `json:"reapplied,omitempty"`
	// Summary is one sentence, ready to show.
	Summary string `json:"summary"`
}

func (r *RepairReport) summarize() {
	var did []string
	if r.Undone > 0 {
		did = append(did, fmt.Sprintf("took back %d network change(s) a run that is gone had recorded", r.Undone))
	}
	if n := len(r.Removed); n == 1 {
		did = append(did, "gave this host's resolver back")
	} else if n > 1 {
		did = append(did, fmt.Sprintf("gave %d resolver entries back", n))
	}
	if r.Reapplied {
		did = append(did, "applied the routes and the resolver of the running node again")
	}
	if len(did) == 0 {
		r.Summary = "Nothing to repair: this host carries no network changes of a BoundGate node."
		if len(r.LeftAlone) > 0 {
			r.Summary = "Nothing to repair: what is set on this host belongs to a node that is running."
		}
		return
	}
	r.Summary = strings.ToUpper(did[0][:1]) + did[0][1:]
	if len(did) > 1 {
		r.Summary += ", and " + strings.Join(did[1:], ", and ")
	}
	r.Summary += "."
}

// repairHost is the part that needs no node: a journal to replay (only when
// no session holds those changes) and the host's own configuration to sweep.
func repairHost(ctx context.Context, nc netcfg.Configurator, undo bool) (RepairReport, error) {
	var rep RepairReport
	if j, ok := nc.(*netcfg.Journal); ok && undo {
		rep.Undone = j.Recover(ctx)
	}
	if s, ok := netcfg.Sweeper(nc); ok {
		keys, err := s.SweepDNS(ctx)
		rep.Removed = keys
		if err != nil {
			rep.summarize()
			return rep, fmt.Errorf("the host's resolver could not be given back: %w", err)
		}
		rep.LeftAlone = s.LiveDNSKeys(ctx)
	}
	rep.summarize()
	return rep, nil
}

// RepairHost undoes what a daemon that is no longer running left on this
// host's network. It is the daemon-less way back (`boundgate-node -repair`):
// the journal of the run that is gone, and a sweep of the host's own
// configuration for the case that the run was killed before it could write
// the record (docs/SECURITY.md R144).
func RepairHost(ctx context.Context, nc netcfg.Configurator) (RepairReport, error) {
	return repairHost(ctx, nc, true)
}

// Repair is the same way back through a daemon that *is* running, which is
// how the tray, the Mac app and `boundgatectl repair` reach it -- whoever
// needs it is looking at a machine that resolves no names, and should not
// have to find a shell and a flag first (R144).
//
// With no session the journal is replayed, as the daemon-less repair does.
// With a session the journal holds what that session is using, so instead
// the routes and the resolver are applied again: that is the way back when
// the host lost them while the node stayed up. The sweep runs either way,
// and never touches an entry whose tunnel device is still there.
func (n *Node) Repair(ctx context.Context) (RepairReport, error) {
	n.mu.Lock()
	s := n.sess
	n.mu.Unlock()
	rep, err := repairHost(ctx, n.net, s == nil)
	if err != nil {
		n.log.Error("repair: the host's resolver could not be given back", "err", err)
		return rep, err
	}
	if s != nil && s.spoke != nil {
		s.spoke.recheckRoutes()
		rep.Reapplied = true
		rep.summarize()
	}
	n.log.Info("repair", "undone", rep.Undone, "removed", len(rep.Removed),
		"left_alone", len(rep.LeftAlone), "reapplied", rep.Reapplied)
	return rep, nil
}
