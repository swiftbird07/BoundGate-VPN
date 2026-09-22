# Replies the way they came (reply_via_arrival)

A server at home, a NAS for example, can do two things at the same time:

* host services that the router forwards from the internet (port forward on
  the Fritz!Box);
* send everything it starts itself through BoundGate, to an exit node, where
  the hub's policies decide what it may reach and the flow log shows
  where it wants to go.

With profile `full` alone these two get in each other's way. The routes of
the exit node (0.0.0.0/1 and 128.0.0.0/1) also catch the answers to the
forwarded connections. The answers go into the tunnel instead of back to the
router. The hub denies them, and a client would drop them anyway, because
they would come from the exit's address. Connections through the tunnel keep
working, so it looks as if the services only broke "from outside".

```yaml
# node.yaml (Linux, not on hubs)
profile: full
reply_via_arrival: true
```

## How it works

Routing by connection instead of by destination:

* A connection that comes in from outside to this host gets a connection
  mark (nftables, table `inet boundgate_arrival`). "From outside" means not
  through the tunnel, and to one of the host's own addresses. That covers
  ports Docker publishes too, because the mark is set before Docker's DNAT.
  Every packet of such a connection carries the mark, forwarded replies from
  containers included.
* The routes through the tunnel go into their own table (5184) instead of the
  main table. The policy rules are:

  ```
  5180  fwmark 0x4000/0x4000 lookup main          replies of connections from outside
  5181  lookup main suppress_prefixlength 0       the LAN, host routes to hubs and control plane
  5182  lookup 5184                               the tunnel: 0/1, 128/1, the overlay, …
  ```

* Marked packets take the main table and leave through the gateway they came
  from. Everything the host or its containers start has no mark and goes
  through the tunnel.

`boundgatectl down` removes the rules, the table and the nftables table. A
daemon that died does it at its next start (journal).

## What it needs

* Linux with nftables (`fib`, `ct mark`) and policy routing, and the node with
  host networking and `NET_ADMIN`, as for every node.
* The hub's policies must allow what the host may reach through the exit
  node. The flow log at the hub shows what it asks for.

`make test-arrival` checks it with a real kernel in a privileged container:
* An internet client behind a router reaches a service on the host and a
  published container port.
* Without the option both answers fall into the tunnel.
* The host's and the container's own connections go into the tunnel.
* `down` leaves nothing behind.
