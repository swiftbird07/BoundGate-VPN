# Routing profiles

A profile says which of the networks the hubs advertise a node routes through
the overlay. The overlay pool itself (the peers' addresses) is always routed;
a profile is about everything behind the peers: LANs of subnet routers and
the `0.0.0.0/0` of exit nodes.

| Profile | Routes | For |
|---|---|---|
| `full` (built in, the default) | everything the hubs advertise, including an exit node's default route | laptops and phones that should leave through the exit node |
| an `include` profile | only the listed networks, and only where a hub advertises them (the intersection; the more specific prefix wins) | servers, subnet routers, workloads: a machine that must keep its own default route |

A server that takes an exit node's `0.0.0.0/0` sends all its own traffic
through the hub, where the policies decide about it: what no policy permits
is denied, and with the default route gone through the tunnel the machine
loses its own internet, its other VPNs and everything not in the overlay.
That is why `deploy/prod/node/node.yaml.example` says a server needs an
`include` profile.

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

`boundgatectl profiles` lists what the daemon found, `boundgatectl up
-profile <name>` switches for one session, `boundgatectl status` shows the
routes in effect. A network in the profile that no hub advertises is simply
not routed (`not routed` in the status names overlaps with the machine's own
networks, which are refused on every profile).
