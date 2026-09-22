# macOS node (M5)

`boundgate-node` runs on macOS as an **endpoint**: the same daemon, identity
stack and control channel as on Linux, with a macOS network backend. It is
cross-compiled in the box (`make build-darwin`, no cgo) and is the one part
of the prototype that deliberately runs on the Mac host.

Accepted on 2026-09-17: `deploy/macos/e2e.sh` passes on macOS 26 (arm64)
against the compose lab, including the `kill -9` recovery.

The app with a menu-bar UI on top of this daemon is described in
MACOS-APP.md (M8).

## What is different on macOS

| Topic | macOS |
|---|---|
| Tunnel device | `utun` through `golang.zx2c4.com/wireguard/tun` (kernel control socket, needs root). `tun_name` other than `utun`/`utunN` means "next free unit"; the actual name is in `boundgatectl status` |
| Address | point-to-point: `ifconfig utunN inet <ip> <ip> netmask 255.255.255.255 mtu 1280 up`; the overlay pool is a route like any other |
| Routes | `route -n add -inet -net <prefix> -interface utunN` (`change` if it exists), `route -n delete …` on the way down |
| Bypass routes | hubs, control plane and IdP stay reachable outside the tunnel: `route -n get <host>` tells gateway and interface, `route -n add -host <host> <gateway>` (or `-interface` on-link) pins them. Loopback targets need none. A host currently routed through another `utun` (a second VPN) is refused rather than pinned there |
| Roles | endpoint only: forwarding and NAT answer "macOS nodes are endpoints only" |
| Device key | `key_kind: secure-enclave` or `auto`: a key in the Mac's Secure Enclave ([SECURE-ENCLAVE.md](SECURE-ENCLAVE.md)); `softkey`: a software key in the state directory |
| DNS | the prototype pushes no DNS configuration on any platform yet, so nothing is touched (`scutil` comes with split DNS) |
| Paths | installed: `/usr/local/bin`, `/usr/local/etc/boundgate/node.yaml`, state `/var/db/boundgate`, socket `/var/run/boundgate/node.sock` (the CLI's default on macOS; `BOUNDGATE_SOCKET` or `-socket` override), logs `/var/log/boundgate` |

## Crash safety: the network journal

Every route, bypass route and NAT table the daemon installs is recorded in
`<state_dir>/netstate.json` (0600) and removed from it on teardown; a clean
`down` deletes the file. When a daemon starts and finds the file, the
previous process died without cleaning up: it removes what is listed
("removed network leftovers of a previous run") before doing anything else.
Routes through the tunnel device vanish with the device anyway; **bypass
host routes do not**, and a stale one would pin a hub to the gateway of a
network the Mac has left. The journal exists on Linux as well.

## Changing networks

The same can happen while the daemon runs: the Mac moves to another Wi-Fi
or to a hotspot. The daemon reads the routing socket. When the default
routes outside any utun differ from the last look (`netstat -rn`, at most
every 2 s), it sets every host route to control plane and hubs again on the
new path and reconnects. Defaults over a utun are left out: host routes are
never pinned into a tunnel, and macOS keeps utuns of its own whose IPv6
defaults come and go. The new path is the default route even while a full
profile's /1 halves point into the node's own utun. The log says
"network changed: host routes renewed, reconnecting". Linux (netlink) and
Windows do the same (SECURITY.md R108).

## Overlap guard: a second VPN, an overlapping LAN

Before the daemon touches anything it compares what it is about to route
with the networks the machine already has (every interface except its own):

* a prefix that is **contained in a local network**, or that **contains the
  address of a point-to-point interface** (another VPN's `utun`), is a
  conflict. `0.0.0.0/0` and the `/1` halves are exempt: a full-tunnel
  profile is meant to cover everything;
* if the **overlay pool** conflicts, `up` is refused before a tunnel device
  exists: "the overlay pool 10.21.0.0/16 overlaps 10.21.0.9/32 on utun8 …".
  Nothing was changed; disconnect the other VPN or move the pool;
* a conflicting **announced prefix** is skipped, the rest comes up.
  `boundgatectl status` lists it as `not routed: 192.168.178.0/24 (overlaps
  192.168.178.0/24 on en0)`, JSON field `skipped_routes`;
* `allow_overlap: true` in the node configuration turns the guard off for
  people who know that the more specific route is what they want.

The guard runs on Linux as well. It is a local safety net, not a security
boundary: it keeps a node from silently hijacking the home LAN or another
tunnel's address range (R25, R66).

## Backup and repair of the Mac's network state

A node changes exactly three things on a Mac: it creates one `utun` device,
adds routes through it, and adds bypass host routes. It does **not** touch
DNS, proxies, network services, the firewall or anything under
`/Library/Preferences/SystemConfiguration`. All three kinds of change live
in kernel memory only: the device and its routes disappear with the
process, and a reboot clears everything.

`deploy/macos/netbackup.sh` is there so that this claim can be checked
rather than believed:

```bash
deploy/macos/netbackup.sh backup        # read-only snapshot, no sudo; deploy/macos/backups/<timestamp>/
deploy/macos/netbackup.sh diff          # now against the latest backup: routes, interfaces, DNS, proxies, …
deploy/macos/netbackup.sh restore       # dry run: prints what it would do
deploy/macos/netbackup.sh restore -y    # stops the node, removes routes and host routes that were not
                                        # there before, re-adds a missing default route (sudo)
```

The snapshot holds the routing table (raw, and normalised without the
kernel's cloned and link-layer entries, which change by themselves),
`ifconfig`, `scutil --dns/--proxy/--nwi`, the `networksetup` view of every
service (addresses, DNS, proxies, order), forwarding sysctls, `/etc/hosts`,
`/etc/resolver`, and copies of `preferences.plist` and
`NetworkInterfaces.plist`. The backups are git-ignored: they describe your
network. `e2e.sh` takes one at its start and compares the stable routes
before and after. Last resorts, in this order: `restore -y`, Wi-Fi off and
on (rebuilds the default route and DNS from DHCP), reboot.

## Hub address overrides

Hubs advertise `public_addr` (unsigned). Where that address is not what the
node can reach, `hub_addrs` in the node configuration maps a hub name (or
the advertised address) to what to dial:

```yaml
hub_addrs:
  hub1: 127.0.0.1:15431
```

The hub is still authenticated by its pinned key from the signed binding;
the override only chooses where packets go. Uses: the compose lab from the
Mac, port forwards, split-horizon DNS.

## Lab: a Mac node against the compose hubs

```bash
make compose-up build-darwin
deploy/macos/dev.sh run                 # daemon in the foreground (sudo); state under deploy/macos/state
deploy/macos/dev.sh ctl enroll          # prints the fingerprint; pending in the admin UI
deploy/compose/setup-dev.sh approve mac # or confirm in the UI and run the sign command
deploy/macos/dev.sh ctl up
deploy/compose/setup-dev.sh login mac   # or `dev.sh ctl login` and open the URL (the fake IdP logs you in)
curl http://10.60.0.10                  # "Name: target", through a hub
deploy/macos/dev.sh ctl down
deploy/macos/dev.sh check               # no utun address, no routes, no journal
deploy/macos/e2e.sh                     # all of the above with assertions, plus a kill -9 recovery
```

* The control plane is reached on `127.0.0.1:18443` (HTTP/3, falling back to
  TCP), the fake IdP on `http://idp.localhost:19000`.
* **UDP**: Colima's default port forwarder (`portForwarder: ssh`) forwards
  TCP only, so the hubs' UDP/443 is not reachable from the Mac. `dev.sh run`
  therefore starts `boundgate-udpbridge`, a lab-only UDP-over-TCP shim
  (Mac side `127.0.0.1:15431/15432` ⇄ TCP `24431/24432` ⇄ lab side ⇄ hub
  UDP/443). QUIC runs end to end through it. With `portForwarder: grpc` in
  `~/.colima/default/colima.yaml` the published UDP ports `14431/14432`
  work directly: `BRIDGE=0 deploy/macos/dev.sh run`.
  `boundgate-udpbridge -probe host:port` tells whether a QUIC server
  answers over UDP (a version-negotiation probe, no handshake).
* The profile `mac-lab` routes only `10.60.0.0/24`. The lab's second network
  `192.168.178.0/24` is a Fritz!Box default; routing it into the lab would
  cut the Mac off from a real home LAN with that prefix (R25).
* Once an admin passkey exists the lab scripts need
  `deploy/compose/state/control/api.token` (DEV.md).

## Installing as a LaunchDaemon

```bash
sudo deploy/macos/install.sh install my-node.yaml    # copies binaries, config (0600), plist; starts the daemon
sudo boundgatectl enroll
sudo deploy/macos/install.sh uninstall               # keeps /var/db/boundgate (the device identity)
```

The daemon runs as root (utun and the routing table need it); the socket is
`0660 root:wheel`, so `boundgatectl` needs `sudo` or group membership.
`KeepAlive` restarts a crashed daemon, which then clears the leftovers of
its predecessor through the journal. Unsigned binaries: Gatekeeper does not
apply to binaries built locally; a distributed build needs a Developer ID
signature and notarization.

## Risks

See SECURITY.md R61–R66.
