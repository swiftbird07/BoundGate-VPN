package node

import "time"

// Power save (Config.PowerSave, on by default in the phone apps). A phone's
// radio stays in its high-power state for seconds after every packet, so
// what costs battery is how often something is sent, not how much. A node
// that sends every 10 s keeps the radio awake around the clock; at 22 % in
// 3.5 hours in the background (iPhone, 2026-09-23) BoundGate led the list.
//
// With power save a quiet node sends nothing:
//
//   - hub tunnels without keep-alives; a tunnel nothing uses ends after
//     quietIdle and is dialed again. A NAT binding that expired in between
//     is replaced by the next packet (QUIC follows the new address), but
//     until then nothing reaches the phone from outside: peers that dial it
//     wait for its next packet or the next dial.
//   - the snapshot polled every quietPoll, and at once after a network
//     change or a sign-in, instead of a long-poll that is never quiet;
//     hubs enforce with their own snapshot, so a phone that learns a change
//     later only shows it later.
//   - heartbeats every quietPoll, logs shipped every quietShip, and the
//     phone's own flows not at all: the hub that carried them logs them.
//   - timers that only tidy up run less often.
const (
	quietPoll = 10 * time.Minute
	quietShip = 5 * time.Minute
	quietIdle = 5 * time.Minute
)

// loginRetry is how long a spoke that a hub refused for lack of a user
// session waits before it asks again on its own. The sign-in itself (and
// a session in a new snapshot) makes it ask at once, so this is only the
// net for a session the node did not hear of.
const loginRetry = 5 * time.Minute

// serverIdle is the idle timeout of the tunnels this node accepts (hub,
// paths). The two sides agree on the shorter one: nodes that keep their
// tunnels alive offer 30 s, phones in power save quietIdle. The accepting
// side sends no keep-alives of its own; the dialing side keeps its NAT
// binding alive when it wants to be reached.
const serverIdle = quietIdle

// tunnelTimers are the idle timeout and keep-alive of the tunnels this node
// dials (to hubs and peers); a negative keep-alive sends none.
func (n *Node) tunnelTimers() (idle, keepAlive time.Duration) {
	if n.cfg.PowerSave {
		return quietIdle, -1
	}
	return 30 * time.Second, 10 * time.Second
}

// every is normal, or quiet in power save.
func (n *Node) every(normal, quiet time.Duration) time.Duration {
	if n.cfg.PowerSave {
		return quiet
	}
	return normal
}
