# Routing profiles

A profile says which of the networks the hubs advertise a node routes through
the overlay. The overlay pool itself (the peers' addresses) is always routed;
a profile is about everything behind the peers: LANs of subnet routers and
the `0.0.0.0/0` of exit nodes.

Three are built in; every node has them without a file, and the apps offer
them by what they do:

| Profile | App | Routes | For |
|---|---|---|---|
| `full` (the default) | Full | everything the hubs advertise, including an exit node's default route | laptops and phones that should leave through the exit node |
| `lan-only` | LAN only | the private networks the hubs advertise: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (shared, CGNAT), `fc00::/7`; the internet stays on this machine's own connection | reaching the LANs behind subnet routers without giving up the local internet |
| `wan-only` | WAN only | everything the hubs advertise *except* those private networks: the internet through an exit node, the LANs behind the hubs not at all | a café Wi-Fi: the traffic leaves through the exit node, the home LAN stays out |

`lan-only` and `wan-only` split `full` between them: no address is routed by
both, and every address `full` routes is routed by one of them. Peers stay
reachable on all three — the pool is routed by itself, and so are the
resolvers the hub offers (`dns`). A file in the profiles directory named
`lan-only` or `wan-only` replaces the built-in one on that machine; `full` is
always everything.

Beyond those:

| Profile | Routes | For |
|---|---|---|
| an `include` profile | only the listed networks, and only where a hub advertises them (the intersection; the more specific prefix wins) | servers, subnet routers, workloads: a machine that must keep its own default route |
| an `exclude` list | taken out of whatever the mode chose, also out of a larger advertised network: `0.0.0.0/0` without `10.0.0.0/8` becomes the routes around it. With `exclude` and no `networks`, the mode is `full` ("everything but") | leaving out one network, e.g. a LAN this machine reaches some other way |

A server that takes an exit node's `0.0.0.0/0` sends all its own traffic
through the hub, where the policies decide about it: what no policy permits
is denied, and with the default route gone through the tunnel the machine
loses its own internet, its other VPNs and everything not in the overlay.
That is why `deploy/prod/node/node.yaml.example` says a server needs an
`include` profile, and why `setup.sh` asks which networks a node should route
and writes `lan-only` unless something else is chosen.

A node never routes a network it announces itself, whatever the profile says:
it reaches that network on its own, and a route through a hub would send its
own traffic for it back into the tunnel (R138). Such a network stands under
`not routed` in the status, next to the overlaps.

An iPhone with `full` takes the exit node's default route and then resolves
names only through the resolvers the hub offers (hub option `dns`). Without
them it resolves nothing (docs/DEPLOY.md, "The hub"; docs/IOS.md).

## Writing one

`profiles/<name>.yaml`, mounted read-only at `profiles_dir` (the node
container: `./profiles:/etc/boundgate/profiles:ro`), named in `node.yaml`:

```yaml
name: site
routing:
  mode: include
  networks:
    - 10.20.0.0/16        # the LAN behind the hub
```

```yaml
profile: site
profiles_dir: /etc/boundgate/profiles
```

Everything but one network:

```yaml
name: not-home
routing:
  exclude:
    - 192.168.178.0/24
```

`boundgatectl profiles` lists what the daemon found, `boundgatectl up
-profile <name>` switches for one session, `boundgatectl status` shows the
routes in effect. A network in the profile that no hub advertises is simply
not routed (`not routed` in the status names overlaps with the machine's own
networks, which are refused on every profile).

## Names

A profile decides which networks are routed, not where names are resolved.
Those are two questions: a node whose profile routes nothing of the LANs can
still be made to resolve through the hub, and it should be, because the hub
only learns what a name stands for when it sees the query (`resolver: hub`,
the default; [ACL.md](ACL.md)). The resolvers a hub offers are reached over
the tunnel through a host route of their own, whatever the profile says.

## Switching while connected

`boundgatectl profile <name>` changes the profile of a running node. Only the
kernel routes change: the tunnels, the overlay address and the session stay as
they are, so nothing reconnects and no flow is interrupted that both profiles
route. Routes the new profile drops disappear at once, which is the point of
the command — the way back to a network is one more switch, not a reconnect.

The same choice is in the Mac panel and the Windows tray under "Route": while
the node is up, picking a profile applies it live; while it is down, it is
remembered for the next connection. A hub takes no profile at all — it
advertises networks, it does not route other peers' — and the daemon says so
instead of switching.

A device that belongs to several meshes picks the network together with the
profile ("Work · Full"): the profile is one network's, and switching the
network is a different, bigger thing than switching the route
([NETWORKS.md](NETWORKS.md)).
