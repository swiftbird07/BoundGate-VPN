# Several networks on one device

A device can belong to more than one mesh: "Private" for the servers at home,
"Work" for the company's network. Each mesh is a control plane of its own and
knows this device under a key of its own. The daemon runs **one network at a
time** and switches between them; both at once is a later step (the end of
this page says why).

This is what issue #13 asked for, and only the desktop side of it: the
packet tunnel of the iOS and Android apps stays with the one network its app
is set up for.

## What a network is

| | |
|---|---|
| `id` | short name, typed in commands and the directory name (`work`) |
| `name` | what the user calls it ("Work") |
| `control_addr` | its control plane, `host[:port]` |
| `control_server_name` | the TLS name of the node channel, if it is not `nodes.<host>` |
| `node_name` | what this device calls itself there |
| `dir` | its state directory, relative to the state root; empty means the root itself |
| `last_enrollment` | what its control plane said last: a network that is not running has no control channel to ask |

The list is `<state>/networks.json`, with `current`: the network that runs.

## Where the state lives

The network a device already had **keeps the state root**. Nothing moves, the
device key stays, the fingerprint its control plane knows stays the same, and
`settings.json` stays readable for an older version of the daemon. A device
with one network therefore has exactly the layout it always had:

```
/var/lib/boundgate/
  settings.json      the one network's control plane
  device.key         its key
  control.pin  admin_trust.json  admin_keys  enrollment.json
  netstate.json      the cleanup journal (one for the daemon)
  networks.json      once there is a list
```

Every **further** network gets `<state>/networks/<id>/` (0700) and
`node.Config.StateDir` points there, so key, pinned control plane, admin key
list and enrollment take the paths they always took -- one set per network:

```
/var/lib/boundgate/networks/work/
  device.key  control.pin  admin_trust.json  admin_keys  enrollment.json
```

Two consequences worth knowing:

* **Each network sees a different device.** The keys differ, so the
  fingerprints differ: a new network means enrolling again, comparing the
  control pin again, and being approved again.
* **The cleanup journal stays one** (`netstate.json` in the root). After a
  crash the next start removes the leftovers of whichever network was
  running, which is why it does not live inside a network's directory.

## Switching

```bash
boundgatectl networks                      # * marks the one that runs
boundgatectl network add -control vpn.corp.example -name Work
boundgatectl network select work -profile full
boundgatectl network remove work
```

A switch is: write down the choice, answer, end the node. Ending the node
takes its routes, its NAT rules and the host's resolver with it, so the next
network starts on a machine that has nothing of the old one left
([SECURITY.md](SECURITY.md) R143). The overlay has to be **down** before a
switch; `boundgatectl down` or the app's disconnect does that.

`-profile` is what the network comes up in once its control plane approves
the node: someone who picked "Work · Full" in an app has said enough, and the
daemon does the `up` itself.

`boundgatectl network remove ID` gives up a network: a network with a
directory of its own loses that directory and with it its device key, which
belonged to that control plane and is of no use anywhere else. The network
that owns the state root instead gives up what ties it to its control plane
-- its settings, its pin, the admin key list, the bindings it has seen -- the
same as `boundgatectl reset`, because the root also holds the daemon's own
files. Revoke the node in that network's admin UI afterwards; the control
plane cannot tell on its own that the device is gone.

`boundgatectl reset` keeps its meaning: forget the network this daemon is in.
With another network in the list the daemon continues there, otherwise it goes
back to setup mode. `reset -new-identity` is unchanged: the same network, a
new key.

## The IPC

On the daemon's socket, and in setup mode as well, so an app adds its first
network the same way it adds a second one later:

| Method | Path | Body | |
|---|---|---|---|
| GET | `/v1/networks` | | `{current, networks[], single?}` |
| POST | `/v1/networks` | `{name, control_addr, control_server_name?, node_name?, select?, profile?}` | the new network; with `select` the daemon switches after answering |
| POST | `/v1/networks/{id}/select` | `{profile?}` | 409 while the overlay is up |
| DELETE | `/v1/networks/{id}` | | 409 for the running network while it is up |

`single` is set when this daemon holds the one network it was given, and says
why: its control plane stands in its configuration file (`control.addr`), it
is a separated node whose sandbox opens exactly one state directory
([PRIVSEP.md](PRIVSEP.md)), or it is an app's packet tunnel. The list then
has that one network in it, so a client needs no second code path, and the
other three endpoints answer 409 with the same reason.

The status carries `network_id` and `network_name` while a daemon knows
several; with one network both are empty and a client that knows nothing
about networks sees what it always saw.

## Servers

A server keeps `control.addr` in `/etc/boundgate/node.yaml` and has one
network, on purpose: its control plane is part of how it was installed, not
something to pick at runtime. `deploy/prod/setup.sh` writes exactly that.

## Not yet

**Two networks at once.** Two sessions with their own tunnel device on one
machine is a bigger thing than switching: the default route, the overlay
pools, the host's resolver and the bypass routes would have to be shared
between them, and each conflict has to be decided rather than discovered.
One network at a time is what the apps need to be useful, and the decision of
2026-10-20 was to ship that first.

**Phones.** The embedded core (iOS, Android) stays single-network: one app,
one extension, one key store.
