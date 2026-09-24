# Power save

A phone's radio stays in its high-power state for several seconds after
each packet. What costs battery is how often something is sent, not how
much. A node that sends a packet every 10 s keeps the radio awake the
whole time.

On 2026-09-23 the iPhone app topped the battery list: 22 % in 3.5 hours in
the background. Its `tunnel.log` and the hub's log showed why:

| What | How often |
|---|---|
| Keep-alive from the phone to the hub | every 10 s |
| Keep-alive from the hub to the phone | every 10 s |
| Keep-alive on the control channel (QUIC PING or HTTP/2 ping) | every 10 s |
| Snapshot long-poll, heartbeat | every 30 s each |
| Flow records of the phone's own connections to the control plane | every 5 s |
| `wake()` of the packet tunnel: reconnect the control channel, redial hubs | up to 200 times an hour |
| Without a user session: a new tunnel attempt (full handshake) | every 2–30 s, all night |

## Power save mode (node option `power_save`)

The phone apps turn it on (embed: `ios`, `android`; `"power_save": false`
turns it off). A daemon can set `power_save: true` in `node.yaml`, for
example on a laptop. A node in power save sends nothing while it is idle:

* **Hub tunnels with a keep-alive every 2 minutes** instead of every 10 s:
  seldom enough for the radio to sleep in between, often enough that most
  NAT mappings survive (they are usually kept for 2 minutes or more), so
  what the hub sends unasked (a push notification through the tunnel, a
  peer's relay pairing) usually gets through. A tunnel with no traffic at
  all ends after 5 minutes and is dialed again.
* **Snapshot polled every 10 minutes** instead of the long-poll. It is also
  polled at once after a network change, after a sign-in, and when a hub
  refuses the tunnel. Between polls there is no open connection.
* **Heartbeat every 10 minutes.** The admin UI counts phones (`ios`,
  `android`) as online for 11 minutes after a heartbeat.
* **Logs shipped every 5 minutes.** The phone's own flows are not shipped
  at all; the hub or peer that carried them logs them.
* **Housekeeping timers run less often:** flow expiry every 30 s, session
  checks once a minute. The 2-s check of the local networks is off, because
  the platform reports network changes.

## For every node

* **Hub and control plane send no keep-alives.** Clients keep their own
  connections alive, so nodes that are not in power save behave as before:
  10 s keep-alives, 30 s idle timeout. The hub accepts idle times up to
  5 minutes, and each tunnel uses the shorter of the two sides' values.
* **Without a user session a spoke waits.** After a 403 it asks again only
  when the session appears (sign-in, new snapshot), or after 5 minutes at
  the latest. A network change no longer redials hubs that refused the
  tunnel for lack of a session.
* **iOS:** `sleep()`/`wake()` do nothing. The path monitor reports real
  network changes and logs only those, not every link quality estimate.

## Network changes and dead tunnels (every node)

Without keep-alives every 10 s a dead tunnel is no longer noticed within
30 s. Three things take the place of that, for every node:

* **A network change moves the tunnels** (`Node.NetworkChanged`, on a
  daemon `RoutesChanged`): every QUIC tunnel gets a new UDP socket and the
  connection migrates to it (RFC 9000 §9: the hub validates the new path
  and answers there), with its address, routes and flows intact. This is
  the fix for the iPhone that stayed "not connected" on 5G on 2026-09-23:
  iOS keeps an existing socket on cellular after Wi-Fi came up, and back
  again, so the tunnel sat on the wrong network until it timed out. A
  tunnel over TCP or over a relay cannot move; it ends and is dialed
  again. A change during a move cancels it; a move the hub does not answer
  within 8 s ends the tunnel.
* **Liveness on demand** (`transport.ClientTunnel`): a tunnel into which
  10 packets went over 30 s without one coming back is probed from a new
  socket. If the hub answers (the NAT mapping had vanished, the old socket
  sat on a dead network), the tunnel continues there; if not, it ends
  (`ErrCodeNoAnswer`) and is dialed again. Nothing is sent while the
  tunnel is idle.
* **Stateless resets** (RFC 9000 §10.3): every node keeps a key in
  `reset.key` in its state directory and answers packets of connections it
  does not know, after a restart, with a stateless reset. A client that
  sends into a tunnel the hub has forgotten learns at once instead of at
  its idle timeout.

## What it costs

* **An idle phone may be unreachable from outside for up to 2 minutes.**
  A NAT mapping that expires before the next keep-alive lets nothing
  through until the phone sends again: not a peer dialing it over a relay,
  not the hub. The relay pairing waits for the phone's next packet.
* **A phone learns of changes up to 10 minutes late:** new policies, a
  revocation, a hub list. Enforcement does not depend on this. Hubs enforce
  with their own snapshot, which they long-poll, and a revoked or expired
  phone is cut off by the hub (SECURITY R112).
* **A hub notices a vanished phone after up to 5 minutes** instead of 30 s.
  A new tunnel from the same device replaces the old one at once.
