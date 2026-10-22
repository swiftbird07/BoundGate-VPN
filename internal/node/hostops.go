package node

import (
	"context"
	"log/slog"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

// hostOp is how long one change to the host's network may take. Each change
// gets its own deadline instead of a shared budget: on 2026-10-22 a single
// `route delete` on a tunnel device that had just gone hung for the whole
// five seconds of the shared one, and everything behind it in the queue --
// the other route, and the resolver -- was cut off with the time already
// spent. Giving the resolver back is last in that queue and must never
// depend on how long the routes took (R144).
const hostOp = 5 * time.Second

func opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), hostOp)
}

// giveBackResolver points the host at its own resolver again. It is the one
// host change that, left behind, takes the whole machine with it: every name
// then goes to an address inside a tunnel that is gone, macOS asks no one
// else (measured, docs/SECURITY.md R140), and nothing on the machine
// resolves a name until someone removes the entry.
//
// So it gets three tries with a deadline each, and when it still fails it is
// an error with the way out in it -- not a warning. The journal keeps its
// record until the removal really succeeded, so the next start of the daemon
// and `boundgate-node -repair` undo it too.
func giveBackResolver(log *slog.Logger, l netcfg.LinkDNSConfigurator, ifname string) error {
	var err error
	for try := 0; try < 3; try++ {
		ctx, cancel := opCtx()
		err = l.SetLinkDNS(ctx, ifname, nil)
		cancel()
		if err == nil {
			if try > 0 {
				log.Info("the host has its own resolver back", "iface", ifname, "tries", try+1)
			}
			return nil
		}
	}
	log.Error("THE HOST IS STILL POINTED AT THE TUNNEL'S RESOLVER: names cannot be resolved on this machine while that lasts. Undo it with `sudo boundgate-node -repair` (the next start of the daemon does it too)",
		"iface", ifname, "err", err)
	return err
}
