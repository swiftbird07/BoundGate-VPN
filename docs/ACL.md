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
| spoke, on a path with another spoke (PATHS.md) | arrive from that peer's tunnel, whichever side dialed (into the node itself or the LAN behind it) | the tunnel peer (authenticated by mTLS by this node) |
| any node | it starts itself (from its host stack) | not decided here: the flow is *tracked* so that return traffic is matched; the receiving node decides |

So a spoke-to-LAN flow over a hub is decided twice: on the hub (as transit)
and on the router (as ingress). Once the two spokes have a path of their own
the hub is out of it and the router decides alone. Both use the same engine and the policies the control
plane scoped to them. Traffic that reaches a node without any decision does
not exist: an unknown source is denied, a stale snapshot (older than
`max_age_seconds`) denies everything, and a policy that does not compile is
skipped (and reported by `boundgatectl status`), never treated as a permit.

## Entity model

Policies talk about these entities:

| Entity | Attributes | Parents (`in`) |
|---|---|---|
| `BoundGate::Node::"<node id>"` (principal, or owner of a destination) | `name`, `kind` (`interactive`/`workload`), `roles` (set), `overlay_ip` (ipaddr), `hardware_bound`, `tags` (set), `platform`, `key_kind`, `has_session` | `BoundGate::Role::"<role>"` for every granted role; `BoundGate::Tag::"<tag>"` for every tag; `BoundGate::User::"<subject>"` while the node has an active user session |
| `BoundGate::User::"<subject>"` | `subject`, `email`, `username`, `groups` (set) | `BoundGate::Group::"<name>"` for every OIDC group |
| `BoundGate::Host::"<ip>"` (resource: the destination of a flow) | `ip` (ipaddr), `port`, `protocol` (`tcp`/`udp`/`icmp`/number), `sni` (only when a TLS ClientHello was seen), `dns_name` (only for DNS queries), `resolved_names` (set; the names this node resolved to the address for this principal, see the dynamic access list) | `BoundGate::Network::"<prefix>"` for the overlay pool and every announced prefix containing the address; `BoundGate::Node::"<owner>"` (the node with that overlay address, or the announcer of the longest matching prefix) |
| `BoundGate::Network::"<prefix>"` | `prefix` (ipaddr) | the announcing node(s) |
| `BoundGate::Tag::"<tag>"` | | none. A destination is `in` the tags of the node that owns it, through that node |
| `BoundGate::List::"<name>"` (Lists in the admin UI) | `name`, `kind` (`ip`, `dns`, `sni`, `dynamic`) | none. A destination is `in` an `ip` list when its address is inside one of the list's prefixes, in a `dns` list when the DNS query name matches one of its names (a query to a resolver the node knows), in an `sni` list when the TLS server name does (wherever the connection goes: the client writes that name, so pair an `sni` list with an address or port condition for services inside the overlay), and in a `dynamic` list when the question matches, when the principal resolved one of its names to the address, when the server name matches and the address is public, or when one of its address entries contains the destination |
| `BoundGate::Action::"connect"` | | the only action |

`context` carries `protocol`, `port`, `has_session`, and when present `sni`,
`dns_name`, `resolved_names` and `user {subject, username, email, groups}`.

Match users by `subject` or by group. `username` is the IdP's
`preferred_username`, which users can often change themselves, so a
`when { context.user.username == "martin" }` admits whoever renames their
account to `martin`; `email` is empty when the IdP says it is not
verified (OIDC.md).

## Lists

A list is a named set of addresses and prefixes (`ip`), DNS query names
(`dns`), TLS server names (`sni`) or all of that together (`dynamic`, see
below), kept apart from the rules that use it
(Lists in the admin UI, `/api/v1/admin/lists`). Names are lowercase; a
leading `*.` matches any number of labels below the name and not the name
itself (`*.github.com` matches `api.github.com`, not `github.com`; list
both for both). Up to 10 000 entries per list; a node receives the lists
its policies name (the enabled policies scoped to it) with its snapshot,
and a change takes effect within seconds like a policy change. A list no
policy of a node names never reaches that node: a list is the
organisation's data (internal hosts, a partner's addresses), and only the
admin's global view shows all of them.

```cedar
// an allow-list: the NAS reaches nothing but these servers
permit(principal == BoundGate::Node::"…nas…", action, resource in BoundGate::List::"allowed-sites");

// a block-list for everyone
forbid(principal, action, resource in BoundGate::List::"ad-domains");

// the LAN, except the hosts on the list
permit(principal, action, resource in BoundGate::Network::"10.60.0.0/24")
  unless { resource in BoundGate::List::"blocked-hosts" };
```

### The dynamic access list

An `ip` list decides by address, a `dns` list by the question of a DNS
query, an `sni` list by the TLS server name — each of them sees one side of
a destination. A **dynamic** list is the whole destination: it holds names
and addresses together, and a name counts however the enforcing node can
see it.

```
*.github.com          a name, with the usual wildcard
myip.wtf
10.60.0.10            a plain address
10.60.0.64/26         a prefix
192.168.178.20-192.168.178.29   a range
10.60.0.11:443        an address and a port
10.60.0.12:8000-8100  a port range   ([2001:db8::1]:443 for IPv6)
```

A permit that names such a list does three things at once:

1. **The DNS query is answered.** The destination of a query whose question
   is in the list is in the list, so the resolution goes through and comes
   back (a hub lets DNS to the resolvers it offers through anyway, see
   `dns` in `DEPLOY.md`). The question counts only on the way to a resolver
   the node knows (`dns`, `dns_learn_from`): to any other address a permitted
   name would open UDP to whatever listens on port 53 there, so a query to
   `8.8.8.8` needs an address permit like any other traffic.
2. **What the answer names is open.** The node reads the answers it
   forwards and remembers, *for the device that asked*, which addresses the
   name resolved to (`internal/node/dnsmap`). The connection that follows is
   decided under that name — whether it is TLS, plain HTTP, a database
   protocol or anything else, and whatever port it uses. The entry lives as
   long as the answer's time to live says (at least a minute, at most an
   hour, plus five minutes, because devices cache longer than they are
   told).
3. **The TLS server name still works, as the fallback — on the way to the
   internet.** A device that resolves elsewhere — DNS over HTTPS in a
   browser, a hard-coded resolver, an address typed by hand — teaches the
   node nothing. A TLS connection to a public address is then still decided
   by the name in its ClientHello, exactly like an `sni` list: the handshake
   is allowed, the first payload held back, and the connection opened or
   reset with the name (see Flows below). The name in a ClientHello is
   whatever the client writes there, so it never stands in for a resolution
   inside the overlay: not for an address of the pool, of a network a node
   announces, or of a private range (RFC 1918, 100.64/10). There, a name
   opens a connection only when the node saw this device resolve it to that
   address, or when an address entry of the list names it.

Three conditions guard what a node believes, all fail closed:

* Only answers from a **resolver the node trusts** are read: the resolvers
  it offers its spokes (`dns`), or the ones `dns_learn_from` names. A device
  that asks some other resolver still gets its answer, but must not be able
  to name an address itself — otherwise it would forge a mapping from a
  permitted name to any address it likes (R115).
* Only the **answer to a query that passed** is read: same message ID, same
  question, on the flow the query left on. An answer nobody asked for is
  dropped, whoever manages to send it with the resolver's address.
* Only names a **dynamic list actually holds** are remembered. Everything
  else passes unremembered.

What is learned belongs to the device *and its user session*: the next user
of a shared device starts without the previous user's resolutions.

What the node learned is visible: the flow log and `boundgatectl flows`
carry `resolved_names` for a flow decided that way, so a permit that came
from a resolution five minutes ago is not a mystery. The dry run in the
policy editor takes the same names (`resolved_names` in
`POST /admin/acl/evaluate`).

A node that sees no DNS at all (a spoke whose device resolves over DoH
only) matches a dynamic list by server name (public addresses) and by its
address entries; the names it never saw resolved simply do not match.
Nothing is remembered across a restart.

### DNS flows are decided query by query

A resolver client keeps one socket for many questions, so the first question
of a UDP flow to port 53 does not speak for the others. Every query is
decided under its own name (in a `dns` or `dynamic` list, or `dns_name` in a
policy); one that no permit takes is dropped alone, and the socket stays
usable for the next. A response passes only as the answer to a query that
passed. What does not read as a plain query (one question, no records but an
EDNS option) is decided without a name, as UDP to that address: a permit by
name carries questions, not other data.

### A list as a file: import, export, and a source it follows

A list is a text file: one entry per line, `#` comments and blank lines
ignored, which is what the admin UI's **Export** writes
(`GET /api/v1/admin/lists/{id}/export`) and what **Import…** reads back
(`POST …/import`, `?mode=add` keeps what is there). A JSON array of strings
is read as well, so a list can be kept in whatever form a repository
already has.

A list can also **follow a URL**: with a source the control plane fetches
that file itself every interval (at least a minute, 15 minutes by default)
and replaces the entries with what it finds, so a list lives in a Git
repository next to the rest of the configuration (a raw file URL of GitHub,
GitLab or Gitea), or follows a feed someone else maintains. Only `http` and
`https` addresses, at most 4 MiB, redirects only within the same host and
scheme (never from `https` to `http`), no proxy from the environment; a
private repository can be given one request header (`Private-Token`,
`Authorization`) whose value the control plane keeps and never sends back.
The value belongs to the URL it was entered with: a PUT that changes the
scheme, host or path without giving `source_secret` again drops the value
and the header (another query keeps them), so a changed URL never carries
the old token somewhere else.
An unchanged file costs one conditional request (`ETag`), and only entries
that really changed bump the snapshot. A source that cannot be read leaves
the list exactly as it was, and the reason stands under the list in the UI
and in the control plane's log; **Fetch now** tries again at once. The
reason never quotes the file: a line that is not an entry is named by its
number and length only. The entries of such a list can still be edited by
hand, but the next fetch replaces them (R114).

The control plane can reach networks the admin API's users cannot, so the
address a source resolves to is checked when the connection is made (after
DNS, so a name that changes its answer does not get around it): loopback,
link-local (169.254/16, fe80::/10), multicast, unspecified addresses and
the cloud metadata services (169.254.169.254, fd00:ec2::254,
100.100.100.200; also written as IPv4-mapped or NAT64 addresses) are always
refused. Private ranges (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)
are refused as well unless the control plane's configuration file admits
them, for a Git server on the organisation's own network:

```yaml
list_sources:
  allow_private: true
```

This switch is in the file on the control-plane host, not in the admin API:
an admin account alone cannot open the internal network to the fetch.

A list that a policy refers to keeps its name and kind and cannot be
deleted (409); its entries can change at any time. A policy may only name
lists that exist (400 otherwise). Lists of server names work like
`resource.sni` conditions: in a `forbid`, the TLS handshake is reset when
the name arrives; in a `permit`, the flow is pending until the ClientHello
(see Flows below).

The membership chain `node ∈ user ∈ group` is what makes user-centric
policies short: `principal in BoundGate::Group::"admins"` is true for a node
whose current session belongs to a user in that group, and false the moment
the session ends (the hub then also closes the tunnel, see `OIDC.md`).

Tags are an administrator's labels for nodes (Nodes, "Edit grant"): a few
are offered (`server`, `workstation`, `laptop`, `phone`, `iot`,
`production`, `staging`, `lab`, `critical`, `dmz`, `office`, `home`,
`personal`, `shared`), any other that fits the form works too. They are part
of the signed binding like roles (BINDINGS.md), so a policy may rely on
them: neither the node nor the control plane can give a node a tag.

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

Laptops reach what is tagged `production` only with a hardware key, and
nothing tagged `iot` starts connections to anything but its own kind:

```cedar
permit (principal in BoundGate::Tag::"laptop", action, resource in BoundGate::Tag::"production")
  when { principal.hardware_bound };
forbid (principal in BoundGate::Tag::"iot", action, resource)
  unless { resource in BoundGate::Tag::"iot" };
```

## Scope

A policy has a `scope`: the node ids it is sent to. Empty scope = every
node. Scope is how a large deployment keeps a hub's policy set small and how
a policy that only makes sense on one router stays there. The global admin
view (`GET /admin/snapshot` without `node`, and dry runs without `enforcer`)
contains every enabled policy.

Scope and paths: a policy scoped to hubs only is not enforced on a path
between two spokes, because no hub decides there. A `forbid` that must hold
between spokes belongs on the receiving nodes or, simplest, has no scope; a
`permit` scoped to hubs only lets the flow pass the hub but not the receiving
spoke, on a path as on the hub route. Spokes that must not be reached except
through a hub's decision set `paths.disabled: true`.

## Flows

A node's flow table groups packets into 5-tuples and asks the engine once
per new peer-originated flow. Then:

* **TLS**: the first payload from the originator is checked for a
  ClientHello. When it carries a `server_name`, the flow is decided again
  with `sni`. A flow that turns from permit into forbid is aborted with TCP
  RSTs to both ends (the client sees "connection reset", not a timeout).
  ClientHellos larger than one segment (post-quantum key shares) are
  reassembled up to 16 KB.
* **Permit by name**: a `permit … when { resource has sni && resource.sni
  like "…" }`, or one with `resource in BoundGate::List::"…"` for a list of
  server names, cannot match the SYN, which has no name yet. When such a
  permit is in scope and the SYN is otherwise denied, the flow is *pending*
  (`boundgatectl flows` shows `pending`): the TCP handshake passes, the
  first payload from the client is held back and read, and the flow is
  decided with the name. Permitted, the ClientHello goes on and the flow
  opens (the open event carries the name); anything else (another name, no
  name, not TLS, a server that speaks first) aborts the connection with
  RSTs to both ends, and the deny event carries the name. The server sees a
  completed handshake from the node's address and never a byte of payload
  (SECURITY R102). A handshake without a ClientHello within 10 s is
  reported as denied. UDP has no handshake: a name-based permit for DNS
  (`dns_name`) works on the first packet, which already carries the query.
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

A record is the reporting node's word. The control plane stamps the
reporter (`node_id`, `node_name`, `reported_by`, from the mTLS identity,
whatever the record said), replaces `principal_name` and `owner_name` with
the names in its registry (and drops them for an id it does not know),
and links the record to a session only when that session belongs to the
principal; `principal`, `user` and the rest stay as reported. The Flows
page shows each record under **Reported by**, and a principal other than
the reporter as "per <reporter>". One node may ship 30 batches a minute
(then 429; the node keeps its buffer and tries again).

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
