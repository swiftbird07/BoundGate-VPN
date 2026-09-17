# Access control (M3): Cedar policies, flows and logs

Every flow in the overlay is decided by [Cedar](https://www.cedarpolicy.com/)
policies that admins write in the control plane. Nodes receive the policies
in their registry snapshot and decide locally, per flow, at the point where
traffic enters something they protect. Nothing is permitted until a policy
permits it.

## Where decisions happen

| Node | Decides flows that … | Principal |
|---|---|---|
| hub | arrive from a peer's tunnel (into the hub's own networks, into another peer's tunnel, into a router's LAN) | the tunnel peer (authenticated by mTLS) |
| subnet router / exit node / endpoint (spoke) | arrive from a hub tunnel (into the LAN behind it, or into the node itself) | the node that owns the source address (overlay address or announced prefix); the hub already verified that the source belongs to that peer |
| any node | it starts itself (from its host stack) | not decided here: the flow is *tracked* so that return traffic is matched; the receiving node decides |

So a spoke-to-LAN flow is decided twice: on the hub (as transit) and on the
router (as ingress). Both use the same engine and the policies the control
plane scoped to them. Traffic that reaches a node without any decision does
not exist: an unknown source is denied, a stale snapshot (older than
`max_age_seconds`) denies everything, and a policy that does not compile is
skipped (and reported by `boundgatectl status`), never treated as a permit.

## Entity model

Policies talk about these entities:

| Entity | Attributes | Parents (`in`) |
|---|---|---|
| `BoundGate::Node::"<node id>"` (principal, or owner of a destination) | `name`, `kind` (`interactive`/`workload`), `roles` (set), `overlay_ip` (ipaddr), `hardware_bound`, `platform`, `key_kind`, `has_session` | `BoundGate::Role::"<role>"` for every granted role; `BoundGate::User::"<subject>"` while the node has an active user session |
| `BoundGate::User::"<subject>"` | `subject`, `email`, `username`, `groups` (set) | `BoundGate::Group::"<name>"` for every OIDC group |
| `BoundGate::Host::"<ip>"` (resource: the destination of a flow) | `ip` (ipaddr), `port`, `protocol` (`tcp`/`udp`/`icmp`/number), `sni` (only when a TLS ClientHello was seen), `dns_name` (only for DNS queries) | `BoundGate::Network::"<prefix>"` for the overlay pool and every announced prefix containing the address; `BoundGate::Node::"<owner>"` (the node with that overlay address, or the announcer of the longest matching prefix) |
| `BoundGate::Network::"<prefix>"` | `prefix` (ipaddr) | the announcing node(s) |
| `BoundGate::Action::"connect"` | | the only action |

`context` carries `protocol`, `port`, `has_session`, and when present `sni`,
`dns_name` and `user {subject, username, email, groups}`.

The membership chain `node ∈ user ∈ group` is what makes user-centric
policies short: `principal in BoundGate::Group::"admins"` is true for a node
whose current session belongs to a user in that group, and false the moment
the session ends (the hub then also closes the tunnel, see `OIDC.md`).

## Examples

```cedar
// group members reach the LAN behind node-r
permit(principal in BoundGate::Group::"vpn-users", action,
       resource in BoundGate::Network::"192.168.178.0/24");

// workloads (no user) reach each other
permit(principal, action, resource) when { principal.kind == "workload" };

// hardware-bound devices only, port 443, anywhere in the data centre range
permit(principal, action, resource)
  when { principal.hardware_bound && resource.port == 443 &&
         resource.ip.isInRange(ip("10.60.0.0/24")) };

// never the printer, whoever you are
forbid(principal, action, resource) when { resource.ip == ip("192.168.178.99") };

// TLS to internal hosts only, by name
forbid(principal, action, resource)
  when { resource has sni && !(resource.sni like "*.net407.internal") };

// no DNS lookups for a domain
forbid(principal, action, resource)
  when { context has dns_name && context.dns_name like "*.evil.example" };

// a specific node may reach a specific node
permit(principal == BoundGate::Node::"…node-a id…", action,
       resource in BoundGate::Node::"…node-r id…");
```

Cedar semantics apply unchanged: at least one `permit` must match and no
`forbid` may match. A referenced attribute that does not exist (e.g.
`resource.sni` on a plain TCP flow) is an evaluation error for that policy,
which then neither permits nor forbids; use `has` guards.

## Scope

A policy has a `scope`: the node ids it is sent to. Empty scope = every
node. Scope is how a large deployment keeps a hub's policy set small and how
a policy that only makes sense on one router stays there. The global admin
view (`GET /admin/snapshot` without `node`, and dry runs without `enforcer`)
contains every enabled policy.

## Flows

A node's flow table groups packets into 5-tuples and asks the engine once
per new peer-originated flow. Then:

* **TLS**: the first payload from the originator is checked for a
  ClientHello. When it carries a `server_name`, the flow is decided again
  with `sni`. A flow that turns from permit into forbid is aborted with TCP
  RSTs to both ends (the client sees "connection reset", not a timeout).
  ClientHellos larger than one segment (post-quantum key shares) are
  reassembled up to 16 KB.
* **DNS**: the question name of a UDP/53 query is available as `dns_name`
  before the first decision.
* **ICMP errors** about an existing allowed flow pass with it.
* Verdicts are cached: a denied 5-tuple stays denied for 10 s without
  re-evaluation or repeated logging; allowed flows expire after 30 min
  (TCP), 2 min (UDP), 30 s (ICMP) of silence, 5 s after FIN/RST.
* A new snapshot (policy, session or peer change) re-evaluates every open
  decided flow; flows that are no longer permitted are closed (packets
  dropped from then on, logged with `reason: policy changed`).
* The table holds at most 65536 flows; above that new flows are dropped
  (fail closed) and `boundgatectl status` shows the overflow.

`boundgatectl flows` lists the table with decision, principal, user,
policies, SNI/DNS name and byte counters.

## Logs

Each node writes `flow.jsonl` (stream `flow`) with one record per flow
`open`, `deny` and `close`:

```
event, flow, node_id, node_name, principal, principal_name, local, user,
username, groups, session, src, sport, dst, dport, proto, sni, dns_name,
decision (allow | deny | local), policies (names), reasons (ids), errors,
owner, owner_name, bytes_in, bytes_out, packets_in, packets_out,
duration_ms, reason, reset
```

Nodes ship these records in batches (every 5 s or 500 records; up to 10 000
buffered while the control plane is unreachable) to `POST /api/v1/node/logs`.
The control plane stores them in `log_events` (stream `flow`, retention
`log_retention`) and serves them at `GET /api/v1/admin/flows` with filters
for reporter, principal, user, decision, destination, SNI, DNS name and time.

Hubs ship **tunnel events** on the same route: `reset` when the hub comes
up (closes whatever the control plane still lists for it), `open` when a
peer attaches, `update` with byte counters every 30 s, `close` with the reason (`closed by
peer`, `idle timeout`, `peer revoked`, `user session ended`, …). The control
plane corrects `closed by peer` to `peer revoked` when the peer is a revoked
node (node and hub learn of a revocation at the same moment; whoever closes
first, the cause is the same), reopens a row it had closed for silence when
the hub reports the tunnel again, and keeps one row per tunnel (`GET /api/v1/admin/tunnels`, `?active=1`,
`?node=`, `?since=`), closes tunnels of hubs that fell silent for 3 minutes
and prunes closed ones with the log retention. This is the data behind the
mesh view of M6.5.

## Dry runs and validation

`POST /api/v1/admin/policies/validate {cedar}` parses without storing.
Creating or replacing a policy validates as well (400 with the parser
message). `POST /api/v1/admin/acl/evaluate {node, dst, port, proto, sni?,
dns_name?, enforcer?}` runs the real engine on the current registry state
(sessions included) and returns the decision, the determining policies, the
user and the owner of the destination; `enforcer` selects whose scoped policy
view to use. `./setup-dev.sh eval node-a 192.168.178.10 80` in the lab.

## Limits and known gaps

* Only IPv4 flows exist in the overlay.
* SNI is read from the first ClientHello only; Encrypted ClientHello (ECH)
  hides the name, and a client that resends after a RST is reset again.
* DNS names are seen in queries, not resolved answers; policies cannot
  express "the IP that `x.example` resolved to".
* With two hubs, return traffic may take a different hub than the request
  (R30). That hub then sees a new flow whose principal is the *responder*;
  restrictive policies must permit both directions or the topology must
  keep both nodes on the same primary hub.
* Flow records are best-effort telemetry, not the enforcement record: a
  node under memory pressure drops the oldest buffered records and logs how
  many.
* Cedar schema validation (typed entities) is not used yet; a typo in an
  attribute name is only visible as an evaluation error in the flow log or a
  dry run (R5).
