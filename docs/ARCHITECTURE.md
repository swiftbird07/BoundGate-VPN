# BoundGate Architecture

BoundGate is a device-bound zero-trust overlay with an L3 tunnel. The one
rule everything else follows:

> There is no long-lived secret anywhere whose copy authorizes a second device.

Node identity is a non-exportable hardware key (TPM 2.0, later Secure
Enclave) presented through mTLS. User identity is OIDC. Access is a Cedar
policy decision per flow. The three are separate modules with a one-way
dependency: policy can narrow what identity granted, never widen it.

## Components

| Binary | Runs where | Role |
|---|---|---|
| `boundgate-control` | Server, port 443 | Admin API (SPA from M4), SQLite, node approval, per-node registry snapshots, OIDC logins and user sessions |
| `boundgate-node` | Every participant, as root/daemon | Owns the device key, keeps the control channel, and depending on its granted roles accepts tunnels (hub), dials hubs, announces prefixes (subnet router, exit node), configures TUN/routes/NAT |
| `boundgatectl` | Every participant, as user; admins for `admin sign` | Thin CLI over the node's Unix socket (status, identity, enroll, up, down, login, logout); `admin sign` talks to the control plane directly and signs bindings with the admin's SSH key |

There is no separate agent or gateway. One binary, roles per node:

| Role | Meaning |
|---|---|
| `endpoint` | An interactive or workload node that reaches things |
| `subnet-router` | Announces prefixes behind the node (`routed` or `snat` per prefix) |
| `hub` | Has a public address, accepts tunnels from every other node and routes between them and its own networks |
| `exit-node` | A subnet router for `0.0.0.0/0` |

Roles combine (a Hetzner box is `hub + subnet-router`, a Raspberry Pi at
home is `subnet-router`, a laptop is `endpoint`). Roles and prefixes are
**granted by an admin**; a node can only request them. Orthogonal to the
roles is the **kind**: an `interactive` node is used by a person and needs
a user session (OIDC login) before hubs admit it; a `workload` (server,
router, hub) is admitted on its device key alone. Kind, roles, prefixes
and overlay address are in the admin-signed binding.

```
              control plane (443)          decides: approvals, roles, sessions, ACL, snapshots
             /       |        \
          hub1      hub2     node-r          authenticate: one identity stack everywhere
          /  \      /  \       |
      node-a  node-r  node-a  LAN 192.168.178.0/24
          ║      ║      ║
          ╚══════╩══════╝                    data path: hub-and-spoke, hubs terminate
```

## Data path

Every non-hub node keeps one tunnel to **every** hub in its snapshot. The
first connected hub in snapshot order is the primary; traffic for the
overlay and for announced prefixes leaves through it, return traffic may
arrive through any hub. A hub that stops (or whose tunnel dies) is replaced
by the next connected one; the kernel routes never change, they point at
the TUN device.

```
app / ssh / browser
        ↓ IP packet
      TUN (bg0)                node-a
        ↓ table miss → uplink (primary hub)
   CONNECT-IP (RFC 9484)      HTTP/3 Extended CONNECT + capsules
        ↓
   HTTP Datagram → QUIC DATAGRAM (unreliable, no TCP-over-TCP)
        ↓
   QUIC + TLS 1.3 mTLS         both sides present their device certificate;
        ↓                      the spoke pins the hub's key from the snapshot
      UDP/443  ─────────────►  hub
                                 ↓ source check (overlay address or announced prefix)
                                 ↓ flow table: new flow? → Cedar decision (principal = peer, resource = destination); SNI/DNS inspection
                                 ↓ table: dst owned by another tunnel? → that tunnel (spoke ↔ spoke, LAN behind a router)
                                 ↓ else → TUN → kernel routing → nftables SNAT → hub's own networks
```

On the receiving spoke the same flow table sits between the hub tunnel and
the TUN: flows that arrive from a hub are decided with the owner of the
source address as principal, flows the node starts itself are only tracked.
See `ACL.md` for the entity model, the enforcement points and the flow log.

* The hub **terminates** the tunnel and sees overlay packets. That is the
  same trust as any VPN concentrator and is acceptable because the hub role
  is granted by an admin and part of the signed binding every node verifies.
  End-to-end paths between spokes (direct, or through a non-terminating
  CONNECT-UDP relay) are milestone M7.
* A subnet router is assigned its announced prefixes in addition to its
  overlay address (CONNECT-IP only lets a peer receive for, and send from,
  assigned addresses). In `snat` mode it masquerades overlay sources behind
  its LAN address; in `routed` mode the LAN needs a route back to the pool.
* quic-go provides QUIC/HTTP/3, connect-ip-go provides RFC 9484. BoundGate
  implements neither protocol nor any cryptography (see `TCB.md`).
* 0-RTT is disabled. Session tickets are disabled on the client. Every
  connection performs a full handshake and therefore a fresh proof of
  possession of the device key.
* Only port 443. UDP/443 carries tunnels (hubs) and the HTTP/3 node channel
  (control plane); TCP/443 carries the admin API and, for nodes, the
  fallback when UDP is blocked. Tunnel fallback over TCP is not in the
  prototype.

## Identity chain

```
DeviceKey (TPM2 / softkey)     never leaves the node
   ↓ crypto.Signer
self-signed X.509 cert         carrier for the public key, max lifetime, no CA;
                               the same certificate is client cert (to control
                               plane and hubs) and server cert (hub listener)
   ↓ TLS 1.3
transport.parseDeviceCert      one cert, ECDSA P-256, valid self-signature, not a CA
   ↓ SPKI hash
registry lookup                approved peers only; miss = handshake failure
                               (spoke side: the hub's SPKI must equal the snapshot's;
                               a peer is in the snapshot only if its admin-signed
                               binding verified against the pinned admin keys)
   ↓
transport.AuthenticatedPeer    the only proof of "who is this node"
   ↓
node.hubService.Accept         interactive peer: user session from the snapshot (OIDC login,
                               bound to the node id, never a token); ACL (M3); addresses
   ↓
Tunnel                         packets flow; return traffic routed by overlay address
```

Revocation is "delete the key from the registry": the next handshake fails,
and every hub closes live tunnels of that node with QUIC error
`ErrCodeRevoked`. Certificate lifetimes play no role. Measured in the
compose lab: revoke to tunnel closed in about 7 ms.

## Control plane

One port, two audiences, told apart by the TLS server name:

| SNI | Certificate | Client auth | Serves |
|---|---|---|---|
| `control.example` | WebPKI (dev: self-signed) | none | admin API (cookie sessions from OIDC + passkey, API tokens; ADMIN-AUTH.md), the embedded admin SPA, the OIDC browser callback |
| `nodes.control.example` | the control plane's own long-lived key | device certificate required | node API: enroll, snapshot long-poll, heartbeat |

Nodes pin the node-channel key's SPKI (trust on first use into
`control.pin`, or provisioned in the config) so a fake root in the system
trust store cannot impersonate the control plane; a changed key is refused.

The control plane keeps one `snapshot_version`; every approval, revocation,
grant change and network-settings change bumps it in the same transaction.
Each node long-polls `/api/v1/node/snapshot?since=N` and receives **its own
view**: its record (`self`), the other approved nodes as `peers` (keys,
kind, roles, overlay addresses, prefixes; hubs with their public address),
the user sessions of itself and its peers, policies (M3) and the pool. M3 narrows peers and policies to
what the node may reach. Nodes react to the diff: removed or changed peers
get their tunnels closed, changed hubs get redialed. A snapshot older than
`max_age_seconds` (control plane unreachable) makes the node fail closed.

## Enrollment and approval

1. `boundgatectl enroll` posts the node's claims (name, platform, key kind,
   requested roles and prefixes, public address for hubs) over mTLS. The
   control plane records a **pending** node with the SPKI it saw.
2. An admin compares the fingerprint with what the user reports and
   **confirms** the node with an explicit grant: roles, prefixes with their
   mode, optional overlay address and public address. Nothing requested is
   taken over silently. The node gets a stable overlay address from the
   pool and a one-time sign token is minted.
3. On the machine with the admin's hardware key, `boundgatectl admin sign`
   signs the **binding** (`node_id, spki, key_version, roles, prefixes,
   overlay_ip`) in OpenSSH's SSHSIG format. The control plane verifies it,
   marks the node approved and distributes record, binding and signature.
4. Every node verifies the binding against the admin keys it pinned at its
   own enrollment before it believes the record. Hubs accept the node,
   spokes dial it if it is a hub. The control plane cannot invent or
   upgrade a node.

Details in `docs/ENROLLMENT.md`, `docs/BINDINGS.md` and `docs/API.md`.

## User login

`boundgatectl login` starts an OIDC authorization-code flow (PKCE, nonce)
at the control plane and prints the IdP URL; the browser lands on the
control plane's callback; the control plane verifies the ID token and
stores a **session bound to the node** that started the flow; the session
travels in snapshots. Hubs admit an interactive node only with a valid
session, close its tunnels when the session ends (revoked, logout,
expired) and enforce expiry locally. Nodes never hold tokens and never
talk to the IdP. Details in `docs/OIDC.md`.

## Routing on a node

* Overlay address: `/32` on the TUN plus a route for the whole pool through
  it (hubs: the pool prefix directly on the TUN).
* Effective routes = profile ∩ (union of what the connected hubs advertise).
  Hubs advertise the pool, their own prefixes and every other peer's
  prefixes. The profile chooses a subset (`include`) or everything
  (`full`). `0.0.0.0/0` is installed as two `/1` routes so the host's real
  default route is shadowed, never replaced.
* Host routes for every hub, for the control plane and, during a login,
  for the IdP are pinned outside the overlay before any overlay route
  lands, so control traffic and login always work, also in full-tunnel
  mode.
* Hubs install kernel routes for peer prefixes through the TUN so their own
  host stack and networks reach the LAN behind a router. Each hub's own
  overlay address is reached through that hub's link; hubs do not forward
  for each other yet.

## Access control

`internal/acl` turns a snapshot into Cedar entities (nodes with their roles
and current user session, users with their groups, networks with their
announcers) and decides `Node → Host` requests with the policies the control
plane scoped to the node. `internal/node/flow` is the connection table that
asks once per flow, inspects the first payload for a TLS server name or DNS
question, caches verdicts, counts bytes and emits the flow log. Policies are
edited and validated in the control plane and distributed in snapshots;
`POST /admin/acl/evaluate` runs the same engine for dry runs.

## Logging

All components write JSON Lines per stream under `log_dir` (and to stdout):
`system`, `audit`, `admin-auth`, `user-auth`, `enrollment`, `flow`. Flow
records carry session, user, groups, node, overlay source, destination,
port, protocol, SNI or DNS name, ACL decision and policy names, bytes and
duration. Nodes ship them (and hubs their tunnel open/update/close events)
to the control plane in batches (`POST /node/logs`); the control plane keeps
them in `log_events` and `tunnels` for the admin UI and the mesh view.

## Repository layout

```
cmd/                    boundgate-control, boundgate-node, boundgatectl, boundgate-fakeidp (lab only)
internal/devicekey      DeviceKey interface, SPKI hash; softkey/ (dev), tpm2key/ (M6)
internal/acl            Cedar entities and decisions (nodes, users, groups, hosts, networks)
internal/node/flow      flow table: verdict cache, SNI/DNS inspection, counters, events
internal/devicecert     self-signed device certificate
internal/binding        admin-signed node bindings: canonical JSON, SSHSIG, verification against pinned admin keys
internal/transport      mTLS verification, AuthenticatedPeer, pinned hub client config, pinned control-plane client config, QUIC/CONNECT-IP server + client
internal/registry       per-node Snapshot (self, peers, hubs, sessions, pool), Holder (stale = fail closed), Diff
internal/control        control plane: db/ (SQLite + migrations), snapshot/ (per-node views incl. sessions), api/ (admin, adminauth, node, login, sign, acl, nodelogs), oidc/ (code flow; oidctest/ fake IdP), web/ (embedded SPA build), SNI split
web/                    admin UI: Svelte 5 + Vite + TypeScript (policy builder, sanity check, nodes, sessions, logs, admins)
internal/node           daemon: control loop, session (up/down), dataplane (TUN + table + uplink), hub service, spoke manager
internal/node/forward   packet buffer conventions, destination table (hosts + longest prefix)
internal/node/netcfg    TUN, addresses, routes, bypass routes, forwarding, nftables NAT (Linux; macOS in M5)
internal/node/profile   routing profiles (include / full)
internal/node/ipc       Unix-socket API between boundgatectl and the daemon
internal/node/controlclient  node API client (HTTP/3 with TCP fallback), snapshot long-poll loop
internal/netparse       allocation-free packet header parsing (fuzzed)
internal/servercert     self-signed server certificate helper (control plane names)
internal/logging        JSON Lines streams
deploy/compose          local lab: control, hub1, hub2, node-a, node-r, two targets
docs/                   this file, TCB.md, SECURITY.md, ENROLLMENT.md, BINDINGS.md, OIDC.md, ACL.md, ADMIN-AUTH.md, API.md, DEV.md
```
