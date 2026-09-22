# Paths between spokes (M7)

Until M7 every packet between two spokes went spoke → hub → spoke, and the hub
saw it. Now two spokes open a tunnel with each other and use it instead of the
hub: directly, if one of them announces an address, otherwise through the relay
of a hub. The hub path stays as it was. It carries the traffic until a path
exists, again the moment a path ends, and always for peers that take no part.

```
           hub path (always there)              path (when both take part)
  A ══ tunnel ══ H ══ tunnel ══ B          A ═════════ tunnel ═════════ B
      H decrypts, decides, forwards          direct:  UDP between A and B
                                              relayed: A ── H ── B, H moves
                                                       ciphertext and nothing else
```

## One handshake

A path is the tunnel a spoke runs to a hub, unchanged: QUIC, TLS 1.3 with the
device certificates of both sides, CONNECT-IP. The dialing side pins the SPKI
of the peer from its signed binding (`ClientTLSConfigPinned`); the accepting
side admits only keys its snapshot knows as approved (`ServerTLSConfig`), the
same two functions and the same `transport.Server` a hub uses. There is no
second way to become an `AuthenticatedPeer`.

Through a relay the very same handshake runs inside the hub connection: the
QUIC packets of A↔B travel as HTTP datagrams of A's and B's existing hub
connections. The hub cannot read them, cannot alter them unnoticed and cannot
answer in B's place, because A accepts nothing but B's key.

## The relay

A hub that relays (default; `relay: false` switches it off) serves
CONNECT-UDP (RFC 9298) on its tunnel listener, to the peers it authenticated
with mTLS like every spoke:

| Request | Meaning | Hub checks |
|---|---|---|
| `CONNECT` `:protocol: connect-udp` `/.well-known/masque/udp/<overlay ip>/443/` with `connect-udp-bind: ?1` | "deliver to me what others send to this address" | the address is the requesting node's own overlay address (403 otherwise) |
| the same without the header | "connect me to the node listening there" | the dialer is approved and, if interactive, has a user session: what the hub asks before it admits a tunnel; the target is the overlay address of another approved node; that node listens here (404 otherwise) |

The target is an overlay address, never a socket: the hub opens no UDP socket
for anyone and cannot be used as an open proxy. A dialer's datagrams (context
ID 0, RFC 9298) reach the listener with the dialer's overlay address and a
port the hub chose in front (context ID 2, address, port, payload: the shape
of draft-ietf-masque-connect-udp-listen with a fixed context ID; both ends are
BoundGate nodes, interoperability with other software is not claimed). The
listener's QUIC server sees them as coming from that address and answers to it;
the hub delivers the answer to the matching dialer.

Every spoke listens at every hub it is connected to. A relayed path ends with
the hub connection it runs on, on both sides at once; the hub path takes over
without a gap in the lab, and the path forms again through another hub.

**On the TCP fallback** a node has no stream to spare: the one connection
carries its IP packets as capsules. A relay stream is therefore a second TLS
connection to the same hub, with the same device certificate and the same
pinned key, upgraded to `connect-udp` over HTTP/1.1 and then carrying every
datagram as one DATAGRAM capsule (RFC 9297) whose payload is what the QUIC
side puts in an HTTP datagram. The hub pairs the two sides exactly as it does
on QUIC, and either side may be on either transport. What ends a QUIC node's
relay streams by itself, losing its admission, is done for these connections
in `CloseDevice`: a revoked node or an ended session closes them too. A node
whose network blocks UDP so reaches its peers end to end, at the price of the
fallback's head-of-line blocking.

"Relay pairs approved nodes only" therefore means: both ends are nodes with a
signed binding in the hub's snapshot, the dialer has its session, a revoked
node or an ended session closes the hub connection and with it every relay
stream. Which flows the target accepts is not the hub's to decide: it cannot
see them.

## Who dials, and when

A path is opened on demand: the first packet for a peer (or a network behind
it) that no tunnel owns goes to the hub as before and asks the path manager
(`internal/node/paths.go`) for a path. Of two spokes exactly one dials, so
they do not open two tunnels at the same moment: towards the one that
announces an address if only one does, otherwise the one with the smaller node
id. The other side's first packet, an answer included, reaches the dialing side
over the hub and starts the dial there.

1. The peer announces `public_addr`: dial it directly.
2. Otherwise, or if that fails: ask every connected hub, the primary first,
   to relay.
3. Nothing works: the traffic stays on the hub; the next attempt comes after
   1, 2, 4 … 32 minutes.

A dialed path nothing used for `paths.idle` (5 min) is closed. Default routes
never move to a path: an exit node is chosen by the profile, not by who
answers first.

Where the address comes from is the path signalling: a node requests
`public_addr` at enrollment, an admin can set it (`PATCH /admin/nodes/{id}`,
Nodes page), and the control plane hands it to every peer in the snapshot. It
is not part of the signed binding, as for hubs: a wrong address can only make
the pinned handshake fail.

```yaml
# a spoke that peers can dial
public_addr: "198.51.100.7:4443"
paths:
  listen: ":4443"      # UDP
  # idle: 5m
  # disabled: true     # neither dial nor accept: everything stays on the hub
# a hub
relay: true            # default
```

## The receiving node decides

On a path no hub is in the middle, so the node that takes the traffic in is
the enforcement point (TCB.md rule 6), whichever side dialed:

* the peer is approved in the node's own snapshot (TLS handshake) and, if
  interactive, has a user session, checked at accept, before dialing, every
  10 s and on every snapshot; without it the path is closed, like a hub closes
  the tunnel;
* a packet must come from an address the peer's binding gives it (its overlay
  address, the networks it announces) and be for this node or a network this
  node announces. A spoke never forwards from a path into another tunnel, not
  even an exit node whose 0.0.0.0/0 contains the pool;
* every new flow is decided by the ACL with the peer as principal and logged
  by this node (`enforcer` in the flow log). A `forbid` that a hub enforced
  before is now enforced by the target: same policy, same result, other place,
  provided the policy reaches the target. One scoped to hubs only does not
  (ACL.md, Scope; SECURITY.md R95).

## Size of packets

A relayed connection stays at QUIC's minimum packet size and does not probe
for more: the datagrams of the carrying hub connection are only certain to hold
that. IP packets above 1100 bytes are therefore not sent into a relayed path
but answered with ICMP "fragmentation needed, MTU 1100", so TCP and everything
else that does path MTU discovery adapts within one round trip (a 300 KB
download is part of the lab test). Direct paths discover their MTU like a hub
tunnel.

## Seeing it

`boundgatectl status` lists `path  node-r, relay hub1 (dialed)`; a hub shows
what it relays. The accepting node reports the path to the control plane like a
hub reports its tunnels, so paths appear in the tunnel history and in the mesh
view as an edge between the two spokes (transport `relay`, or `quic` for a
direct one).

## Not in this milestone

* Hole punching (both sides behind NAT, no relay in the data path). The relay
  is the fallback it would need anyway.
* Paths of hubs among each other.
* A spoke is reachable for every approved peer, as it is through a hub. Which
  peers may open flows is the ACL's matter, not the path's.
