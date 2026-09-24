# Control plane API (M4)

One port (443), two audiences. All bodies are JSON.

| Audience | How it is recognised | TLS | Auth |
|---|---|---|---|
| admin | SNI = `server_name` (e.g. `control`) | WebPKI (dev: self-signed `control.crt`) | cookie `bg_admin` (OIDC + passkey, see ADMIN-AUTH.md; non-GET needs `X-Requested-With: BoundGate`), `Authorization: Bearer bgapi_…` (API token) or the bootstrap token while no admin passkey exists; the `/api/v1/sign/…` routes take a one-time sign token instead. Non-`/api/` paths serve the SPA |
| node | SNI = `node_server_name` (e.g. `nodes.control`) | the control plane's long-lived node key (`nodes.crt`), **pinned by nodes** + **required device client cert** | the device certificate itself |

Both are served on TCP/443 (HTTP/1.1, HTTP/2) and UDP/443 (HTTP/3). Nodes
prefer HTTP/3 and fall back to TCP.

Errors: `{"error": "..."}` with 400/401/403/404/409/429/503/500.

## Admin

| Method | Path | Body / query | Result |
|---|---|---|---|
| GET | `/api/v1/admin/me` | | `Admin {subject, email, name, level, via}` (also for `oidc_only` sessions) |
| GET | `/api/v1/admin/overview` | | `{nodes{pending,confirmed,approved,revoked}, active_sessions, active_tunnels, policies, policies_enabled, denied_last_24h, pending_passkeys, signers, snapshot_version}` |
| GET | `/api/v1/admin/auth/status` | (no auth needed) | `AuthStatus`: `level (none\|oidc_only\|full), subject, email, name, via (session\|token\|bootstrap), own_passkeys, own_pending, total_passkeys, bootstrap_active, oidc_configured, passkeys_enabled, rp_id, error?` |
| GET | `/api/v1/admin/auth/login?next=/path` | (no auth) | 302 to the IdP; sets the flow cookie `bg_login`; `next` must be a local path |
| POST | `/api/v1/admin/auth/logout` | cookie | 204; revokes the session |
| POST | `/api/v1/admin/auth/passkey/register/begin` | cookie (`oidc_only` ok) | `{label, bootstrap_token?}` → `{mode (first\|self\|pending), options}` (WebAuthn creation options JSON); 403 first passkey without the bootstrap token |
| POST | `/api/v1/admin/auth/passkey/register/finish` | cookie | the browser's `PublicKeyCredential` JSON → 201 `{id, status (active\|pending), level}`; 409 credential already registered |
| POST | `/api/v1/admin/auth/passkey/login/begin` | cookie | `{}` → `{options}`; 409 `{error, pending}` without an active passkey |
| POST | `/api/v1/admin/auth/passkey/login/finish` | cookie | assertion JSON → `{level: "full"}`; 403 on a bad assertion |
| GET | `/api/v1/admin/passkeys` | | `[PasskeyView]` of every admin |
| POST | `/api/v1/admin/passkeys/{id}/approve` | | `PasskeyView`; 403 own passkey; 409 not pending |
| DELETE | `/api/v1/admin/passkeys/{id}` | | 204 (revoke) |
| GET | `/api/v1/admin/tokens` | | `[TokenView]` without secrets |
| POST | `/api/v1/admin/tokens` | `{name, expires_in? ("720h")}` | 201 `TokenView` + `token` (once) |
| DELETE | `/api/v1/admin/tokens/{id}` | | 204 (revoke) |
| GET | `/api/v1/admin/nodes` | `?state=pending\|confirmed\|approved\|revoked` | `[NodeView]` |
| GET | `/api/v1/admin/nodes/{id}` | | `NodeView` |
| POST | `/api/v1/admin/nodes/{id}/confirm` (alias `/approve`) | `Grant` (roles required for a pending node; empty body on a confirmed node re-issues the token) | `ConfirmResponse`; 400 without roles; 409 if fingerprint mismatch, wrong state, invalid grant, or no admin key registered |
| POST | `/api/v1/admin/nodes/{id}/reject` | | 204; pending/confirmed only |
| PATCH | `/api/v1/admin/nodes/{id}` | `Grant` (all fields optional) | `ConfirmResponse`; a signed field change demotes an approved node to confirmed and returns a new sign token |
| GET | `/api/v1/admin/tags` | | `{defaults: [...], used: [...]}`: the tags to offer in an editor (built in, and carried by some node) |
| DELETE | `/api/v1/admin/nodes/{id}` | | 204 (revoke, also ends the node's user session); 409 unless approved |
| GET | `/api/v1/admin/signers` | | `[SignerView]` incl. removed; `active` = in the signed list |
| GET | `/api/v1/admin/signers/set` | | `{version, hash, genesis_hash, history[]}` of the signed list |
| POST | `/api/v1/admin/signers` | `{name?, public_key}` (authorized_keys line) | 202 `SignerChangeView` (a proposal: `sign_command`, `sign_token`, `added`, `removed`, `affected_nodes`, `signable_by`); 400 for a disallowed key type; 409 if already in the list |
| DELETE | `/api/v1/admin/signers/{id}` | | 202 `SignerChangeView`; 409 if the list would become empty |
| POST | `/api/v1/admin/signers/change` | `{add:[{name?, public_key}], remove:[id]}` | 202 `SignerChangeView`: several changes under one signature; empty body with no signed list yet proposes the registered keys as the first list |
| GET | `/api/v1/sign/signers` | Bearer sign token | `{set, namespace, chain, names, expires_at}`: the canonical list to sign and the current chain |
| POST | `/api/v1/sign/signers` | Bearer sign token, `{signature}` | 200 `{version, hash, signed_by, keys, demoted_nodes}`; 403 not a key of the current list; 409 token used or list changed meanwhile |
| GET | `/api/v1/admin/sessions` | `?all=1` includes ended ones | `[SessionView]` |
| DELETE | `/api/v1/admin/sessions/{id}` | | 204 (revoke; hubs close the node's tunnels); 409 if already ended |
| GET | `/api/v1/admin/identity` | | `{control_pin, spki}`: fingerprint of the node-channel key, what a device shows and asks about at its first contact (ENROLLMENT.md) |
| GET/PUT | `/api/v1/admin/settings/network` | `{pool, max_age_seconds?, renumber?}` | settings; PUT bumps the snapshot. A pool that leaves nodes outside: 409 `{error, outside: [{id, name, overlay_ip, status}]}`, unless `renumber: true`: every such node moves to the same host number in the new pool (10.21.3.7 → 10.25.3.7; 409 and no change if one does not fit), and approved ones go back to `confirmed`, because the overlay address is part of the signed binding: they are out of the network until signed again. Answer: `{pool, max_age_seconds, renumbered: [{id, name, from, to, needs_signature}]}` |
| GET | `/api/v1/admin/snapshot` | `?node=<id>` | the global view, or what that node receives |
| GET | `/api/v1/admin/logs` | `?stream=&node=&actor=&q=&from=&to=&before=&limit=` | `[LogEvent]` newest first |
| GET | `/api/v1/admin/policies` | | `[PolicyView]` |
| POST | `/api/v1/admin/policies` | `PolicyBody` | 201 `PolicyView`; 400 with the Cedar parser message or an unknown scope node; 409 duplicate name |
| GET/PUT/DELETE | `/api/v1/admin/policies/{id}` | `PolicyBody` (PUT replaces everything) | `PolicyView` / 204; every change bumps the snapshot. `PolicyBody`/`PolicyView` carry `group` (a heading for the admin UI, no effect on decisions); a policy that names a list that does not exist is refused (400) |
| POST | `/api/v1/admin/policies/validate` | `{cedar}` | `{ok, error?}` |
| GET | `/api/v1/admin/lists` | | `[ListView]`: `{id, name, kind (ip|dns|sni), description?, entries[], used_by[] (policy names), created_at, created_by?, updated_at, updated_by?, source_url?, source_interval? (seconds), source_header?, source_secret_set?, source_fetched_at?, source_status? (empty: the last fetch worked)}`. The source secret is never part of an answer |
| POST | `/api/v1/admin/lists` | `{name, kind, description?, entries[], source_url?, source_interval? (seconds, at least 60, default 900), source_header?, source_secret?}` (entries: one address, prefix or name each; blank lines and `#` comments are dropped, the rest normalized, sorted, de-duplicated; at most 10 000) | 201 `ListView`; 400 with the first bad entry or a source url that is not http(s); 409 duplicate name |
| GET/PUT/DELETE | `/api/v1/admin/lists/{id}` | as POST; `source_secret` absent keeps the stored one, `""` clears it | `ListView` / 204; 409 when policies refer to the list and the name or kind would change, or on delete; every change bumps the snapshot |
| GET | `/api/v1/admin/lists/{id}/export` | | `text/plain`: the list as a file (one entry per line, a `#` header), the form `/import` and a source read |
| POST | `/api/v1/admin/lists/{id}/import` | the file as the body (text or a JSON array), at most 4 MiB; `?mode=add` adds instead of replacing | `ListView`; 400 with the first bad entry |
| POST | `/api/v1/admin/lists/{id}/fetch` | | fetches the list's source now: `ListView`; 400 without a source; 502 `{error, list}` when the source cannot be read, and the list keeps its entries |
| POST | `/api/v1/admin/acl/evaluate` | `{node, dst, port?, proto?, sni?, dns_name?, enforcer?, draft? {id, name, cedar}, draft_only?}` | `{allow, policies, reasons, errors?, policy_count, policy_errors?, principal, user?, groups?, owner?, owner_name?}` (dry run on live state; `draft` replaces the stored policy with the same id or is added, without being stored; `draft_only` evaluates it alone; 400 if the draft does not parse) |
| GET | `/api/v1/admin/tunnels` | `?node=&active=1&since=&limit=` | `[Tunnel]` newest first: `id, hub_id, hub_name, peer_id, peer_name, peer_addr, opened_at, closed_at?, close_reason, bytes_in/out, packets_in/out, last_report_at` |
| GET | `/api/v1/admin/flows` | `?node=&principal=&user=&decision=&event=&dst=&sni=&dns_name=&from=&to=&before=&limit=` | `[LogEvent]` of stream `flow` (see ACL.md for the attributes) |

`PolicyBody`: `{name, description?, cedar, enabled? (default true), scope?
[node ids; empty = all nodes]}`. `PolicyView` adds `id, created_at/by,
updated_at/by`.

`Grant`:

```json
{
  "fingerprint": "ab12 …",              // optional, must match the node
  "name": "martins-laptop",             // optional rename (unsigned)
  "kind": "interactive",                // interactive (needs a user login) | workload; signed
  "roles": ["endpoint", "subnet-router"],
  "prefixes": [{"prefix": "192.168.178.0/24", "mode": "snat"}],   // routed | snat
  "overlay_ip": "10.21.0.7",            // optional, else the next free address
  "public_addr": "hub1.example:443",    // hubs: what spokes dial; spokes: where peers can dial a direct path (PATHS.md); unsigned
  "tags": ["production", "server"],     // optional. Omitted: none (confirm), unchanged (patch). [] clears. Signed, like roles.
                                        // a-z 0-9 . _ - (max 32, starts with a letter or digit), at most 16; lowercased, sorted; else 400
  "hardware_bound": true                // optional. Omitted: what the node reported (confirm), unchanged (patch).
                                        // false declines a reported hardware key; true without such a report is 409. Signed.
}
```

`NodeView`: `id, name, hostname, platform, key_kind, hardware_bound` (granted
and signed)`, hardware_claimed` (reported by the node)`, spki,
fingerprint, status, kind, requested_roles, requested_prefixes, roles, tags, prefixes,
overlay_ip, public_addr, key_version, signed, signed_by, signed_at,
requested_at, request_ip, confirmed_at, confirmed_by, approved_at,
approved_by, revoked_at, revoked_by, last_seen_at, snapshot_version,
active_tunnels`.

`ConfirmResponse` = `NodeView` plus, while a signature is outstanding,
`sign_token` (`bgsign_…`, 10 minutes, single use), `sign_expires_at` and
`sign_command`.

`SignerView`: `id, name, subject, public_key, key_type, hardware,
fingerprint (SHA256:…), created_at, revoked_at`.

`SessionView`: `id, node_id, node_name, subject, email, username, groups,
login_ip, issued_at, expires_at, ended_at, ended_by, end_reason (revoked |
logout | expired | replaced)`.

`PasskeyView`: `id, subject, email, label, status (pending | active |
revoked), created_at, approved_at/by, last_used_at, revoked_at/by`.
`TokenView`: `id, name, created_by, created_at, expires_at, last_used_at,
revoked_at/by` (+ `token` once at creation).

Levels: a cookie session is `oidc_only` until a passkey assertion; at that
level only `/admin/auth/*` and `/admin/me` answer, everything else is 403
`{"error":"passkey required","level":"oidc_only"}`. A missing CSRF header
on a cookie-authenticated non-GET is 403. The bootstrap token after the
first active passkey is 401 with an explanatory message.

## Browser (no auth)

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/oidc/callback?code&state` | HTML page (user login) or 302 with the admin cookie (admin login); completes the flow the `state` belongs to |
| GET | anything not under `/api/` | the admin SPA (`index.html` for paths without an extension) |

## Sign (one-time token)

| Method | Path | Auth | Result |
|---|---|---|---|
| GET | `/api/v1/sign/binding` | `Authorization: Bearer bgsign_…` | `SignBinding`; 401 unknown/expired token; 409 used token or node not confirmed |
| POST | `/api/v1/sign/signature` | same | `{signature}` (armored SSHSIG) → `NodeView` (approved); 403 signer not registered; 409 signature not over the current grant, or token used |

`SignBinding`: `node_id, name, fingerprint, key_kind, hardware_bound,
roles, prefixes, overlay_ip, public_addr, binding` (the exact bytes to
sign), `namespace` (`boundgate-binding`), `expires_at, signers`
(authorized_keys lines of the active admin keys). Rate limit 30/min per
source IP.

## Node (mTLS)

| Method | Path | Who | Result |
|---|---|---|---|
| POST | `/api/v1/node/enroll` | any device cert | 202 `EnrollStatus` (new, pending) or 200 (known key, current status); 429 rate limited; 503 while no admin key is registered |
| GET | `/api/v1/node/enroll/status` | any device cert | 200 `EnrollStatus` or 404 `{status:"unknown"}` |
| GET | `/api/v1/node/snapshot` | approved (signed) only, 403 otherwise | `?since=N&wait=30s`: 200 `registry.Snapshot` when version > N, else 304 after `wait` |
| POST | `/api/v1/node/heartbeat` | approved only | `{version, active_tunnels}` → 204 |
| POST | `/api/v1/node/login/start` | approved only | `{flow_id, url, expires_at}`; 503 without an IdP, 502 if the IdP is unreachable |
| GET | `/api/v1/node/login/{flow}` | the node that started it | `?wait=30s`: `{status: pending\|done\|failed, session?, error?}` |
| POST | `/api/v1/node/logout` | approved only | 204 |
| POST | `/api/v1/node/logs` | approved only | `{events: [{ts, stream: flow\|tunnel, message, attrs}]}` (≤ 2000 events, ≤ 4 MB) → `{accepted, rejected}`; tunnel events (`reset`, `open`, `update`, `close`) only from hubs; the reporter's id overrides `attrs.node_id` |

Enroll body: `{name, hostname, platform, key_kind, hardware_bound, roles[],
prefixes[{prefix, mode}], public_addr}`. Everything is a claim.

`EnrollStatus`: `{node_id, name, status, fingerprint, roles?, overlay_ip?,
admin_signer_keys[], control_spki}`. Nodes pin `admin_signer_keys` on first
receipt and cross-check `control_spki` with the key they pinned in TLS.

`registry.Snapshot` (per node): `version, generated_at, max_age_seconds,
self {id, name, spki, kind, roles, overlay_ip, prefixes, public_addr,
key_version, binding, signature, signed_by}, peers [same shape], sessions
[{id, node_id, subject, email, username, groups, expires_at}] (own and
peers'), policies [{id, name, cedar}] (enabled and scoped to the node), lists [{name, kind, entries}] (all of them),
pool`. `binding` is the canonical JSON that was
signed, `signature` the armored SSHSIG; nodes verify both before using a
record.

The snapshot version increases with every approval, revocation, grant
change, network-settings change, login, logout, session revocation, session
expiry sweep and policy change (same transaction). Nodes keep `since`
at the last applied version; a restart starts at 0 and receives the full
state. A 403 on the snapshot route tells a node it is no longer approved
(revoked, or demoted to confirmed by a grant change).
