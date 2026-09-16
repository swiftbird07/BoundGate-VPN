# Control plane API (M3)

One port (443), two audiences. All bodies are JSON.

| Audience | How it is recognised | TLS | Auth |
|---|---|---|---|
| admin | SNI = `server_name` (e.g. `control`) | WebPKI (dev: self-signed `control.crt`) | `Authorization: Bearer <bootstrap token>` (M4: OIDC + passkey cookie); the `/api/v1/sign/…` routes take a one-time sign token instead |
| node | SNI = `node_server_name` (e.g. `nodes.control`) | the control plane's long-lived node key (`nodes.crt`), **pinned by nodes** + **required device client cert** | the device certificate itself |

Both are served on TCP/443 (HTTP/1.1, HTTP/2) and UDP/443 (HTTP/3). Nodes
prefer HTTP/3 and fall back to TCP.

Errors: `{"error": "..."}` with 400/401/403/404/409/429/503/500.

## Admin

| Method | Path | Body / query | Result |
|---|---|---|---|
| GET | `/api/v1/admin/me` | | `{subject}` |
| GET | `/api/v1/admin/nodes` | `?state=pending\|confirmed\|approved\|revoked` | `[NodeView]` |
| GET | `/api/v1/admin/nodes/{id}` | | `NodeView` |
| POST | `/api/v1/admin/nodes/{id}/confirm` (alias `/approve`) | `Grant` (roles required for a pending node; empty body on a confirmed node re-issues the token) | `ConfirmResponse`; 400 without roles; 409 if fingerprint mismatch, wrong state, invalid grant, or no admin key registered |
| POST | `/api/v1/admin/nodes/{id}/reject` | | 204; pending/confirmed only |
| PATCH | `/api/v1/admin/nodes/{id}` | `Grant` (all fields optional) | `ConfirmResponse`; a signed field change demotes an approved node to confirmed and returns a new sign token |
| DELETE | `/api/v1/admin/nodes/{id}` | | 204 (revoke, also ends the node's user session); 409 unless approved |
| GET | `/api/v1/admin/signers` | | `[SignerView]` incl. revoked |
| POST | `/api/v1/admin/signers` | `{name?, public_key}` (authorized_keys line) | 201 `SignerView`; 400 for a disallowed key type; 409 if registered |
| DELETE | `/api/v1/admin/signers/{id}` | | 204 (revoke for future signatures) |
| GET | `/api/v1/admin/sessions` | `?all=1` includes ended ones | `[SessionView]` |
| DELETE | `/api/v1/admin/sessions/{id}` | | 204 (revoke; hubs close the node's tunnels); 409 if already ended |
| GET/PUT | `/api/v1/admin/settings/network` | `{pool, max_age_seconds?}` | settings; PUT bumps the snapshot; 409 if an assigned address would fall outside the new pool |
| GET | `/api/v1/admin/snapshot` | `?node=<id>` | the global view, or what that node receives |
| GET | `/api/v1/admin/logs` | `?stream=&node=&actor=&q=&from=&to=&before=&limit=` | `[LogEvent]` newest first |
| GET | `/api/v1/admin/policies` | | `[PolicyView]` |
| POST | `/api/v1/admin/policies` | `PolicyBody` | 201 `PolicyView`; 400 with the Cedar parser message or an unknown scope node; 409 duplicate name |
| GET/PUT/DELETE | `/api/v1/admin/policies/{id}` | `PolicyBody` (PUT replaces everything) | `PolicyView` / 204; every change bumps the snapshot |
| POST | `/api/v1/admin/policies/validate` | `{cedar}` | `{ok, error?}` |
| POST | `/api/v1/admin/acl/evaluate` | `{node, dst, port?, proto?, sni?, dns_name?, enforcer?}` | `{allow, policies, reasons, errors?, policy_count, policy_errors?, principal, user?, groups?, owner?, owner_name?}` (dry run on live state) |
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
  "public_addr": "hub1.example:443"     // hubs: what spokes dial (unsigned)
}
```

`NodeView`: `id, name, hostname, platform, key_kind, hardware_bound, spki,
fingerprint, status, kind, requested_roles, requested_prefixes, roles, prefixes,
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

## Browser (no auth)

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/oidc/callback?code&state` | HTML page; completes the login flow the `state` belongs to |

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
peers'), policies [{id, name, cedar}] (enabled and scoped to the node),
pool`. `binding` is the canonical JSON that was
signed, `signature` the armored SSHSIG; nodes verify both before using a
record.

The snapshot version increases with every approval, revocation, grant
change, network-settings change, login, logout, session revocation, session
expiry sweep and policy change (same transaction). Nodes keep `since`
at the last applied version; a restart starts at 0 and receives the full
state. A 403 on the snapshot route tells a node it is no longer approved
(revoked, or demoted to confirmed by a grant change).
