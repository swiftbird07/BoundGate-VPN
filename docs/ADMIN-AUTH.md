# Admin authentication and the admin UI (M4)

The control plane's admin API has one audience: administrators, in a
browser (the embedded single-page app) or in scripts. M4 replaces the
bootstrap token with proper admin identities and ships the UI.

## Who may administer

Two factors, both mandatory for people:

1. **Identity**: an OIDC login at the organisation's identity provider
   (Authentik). The ID token must carry the admin group (`admin.group`,
   default `admins`) in its `groups` claim; other users are refused at the
   callback ("Not an administrator") and never get a session.
2. **Possession**: a **passkey** (WebAuthn, user verification required)
   registered for that OIDC subject. Roaming keys (YubiKey), platform
   authenticators (Touch ID, Windows Hello) and synced passkeys all work;
   attestation is not requested (`none`).

A browser session therefore has a **level**:

| Level | Set when | May call |
|---|---|---|
| `oidc_only` | the OIDC callback created the session | `/api/v1/admin/auth/*` (passkey ceremonies, logout, status) and `/api/v1/admin/me` |
| `full` | a passkey assertion succeeded, or the first/self-registered passkey was just registered (registration also verifies the user on the authenticator) | everything |

Sessions live in `admin_sessions` (id = the cookie value, `bgadm_…`,
random 256 bit), expire after `admin.session_lifetime` (default 1 h; the
lab uses 8 h), are revoked by logout and listed in the audit stream. The
cookie `bg_admin` is `HttpOnly`, `Secure`, `SameSite=Lax`, path `/`.

### Passkey lifecycle

| Situation | Result of registering |
|---|---|
| no active passkey exists anywhere (fresh control plane) | needs the **bootstrap token** in the request; becomes `active` immediately; the session becomes `full` |
| a `full` admin adds another passkey for themselves | `active` immediately |
| an `oidc_only` admin without passkeys registers one | `pending` until another `full` admin approves it under Admins → Passkeys; self-approval is refused |

Revoking a passkey (any full admin, including one's own) makes it unusable
for new assertions; existing sessions keep their level until they expire or
log out. Passkey credentials (public key, sign counter, flags) are stored
as JSON in `admin_passkeys`; the counter is updated on every login and a
cloned authenticator (counter going backwards) is refused by go-webauthn.

### The bootstrap token

Written to `bootstrap_token_file` on first start. It authenticates as a
`full` admin **only while `CountActivePasskeys() == 0`**. The moment the
first passkey is active it answers 401 with "the bootstrap token is
disabled" wherever it is used. There is no way to re-enable it short of
revoking every passkey. The lab (`setup-dev.sh`, `e2e.sh`) drives the API
with it, which is why the lab never registers a passkey.

### API tokens

`POST /api/v1/admin/tokens {name, expires_in}` (a `full` admin) mints
`bgapi_…` bearer tokens for automation. Only the SHA-256 of the secret is
stored; the secret is shown once. Tokens are `full`, carry the creator's
name in the audit trail (`token:<name>` as actor), can expire and can be
revoked. They are not tied to a passkey: a leaked token is a leaked admin
until revoked, so give them expiries.

### CSRF

The cookie is `SameSite=Lax`, which already stops cross-site POSTs in
current browsers. In addition every non-GET request authenticated by
cookie must carry `X-Requested-With: BoundGate` (the SPA sets it; a form
cannot). Bearer tokens are exempt (no ambient authority).

### Configuration

```yaml
admin:
  rp_id: control.example          # WebAuthn relying party id = the domain in the address bar
  origins: [https://control.example]   # allowed browser origins (default https://<rp_id>)
  group: admins                   # OIDC group that grants admin access
  session_lifetime: 1h
oidc:
  redirect_url: https://control.example/api/v1/oidc/callback   # shared with user logins
```

`rp_id` must be a registrable domain, not an IP address, which is why the
lab pins `rp_id: localhost`. An `rp_id` that does not match the page's
domain makes the browser refuse every ceremony ("SecurityError").

Browsers also refuse WebAuthn on pages with certificate errors, and the
lab's admin certificate is self-signed. The lab therefore has a `devproxy`
service (socat) that publishes the admin name as plain HTTP on
**`http://localhost:18080`**; `http://localhost` is a secure context, so
passkeys work there without touching the Mac's trust store. The lab lists
that origin in `admin.origins` and points `oidc.redirect_url` at it. A
cookie is normally `Secure`; only for a request whose `Host` matches an
`http://` origin the operator listed in `admin.origins` is the flag left
off (such a browser would otherwise drop the cookie). Never list an
`http://` origin in production.

## Flow

```
browser                               control plane                          IdP
  │  GET /api/v1/admin/auth/login?next=/nodes                                   │
  │────────────────────────────────────►│ create admin_login_flow (state, nonce, PKCE)
  │  302 + cookie bg_login=<flow>       │                                        │
  │◄────────────────────────────────────│                                        │
  │  authorize (state, nonce, PKCE) ─────────────────────────────────────────────►│
  │  302 /api/v1/oidc/callback?code&state ◄──────────────────────────────────────│
  │────────────────────────────────────►│ flow by state, cookie must match       │
  │                                     │ exchange code, verify ID token, groups ∋ admin group
  │  302 next + cookie bg_admin (oidc_only)                                      │
  │◄────────────────────────────────────│                                        │
  │  POST auth/passkey/login/begin ────►│ challenge for the subject's active credentials
  │  navigator.credentials.get()        │                                        │
  │  POST auth/passkey/login/finish ───►│ verify assertion, level = full         │
```

The OIDC callback is shared with user logins (M2): the `state` is looked up
among admin flows first, then node flows. A callback without the flow
cookie is refused, so a link captured from one browser cannot finish the
login in another.

`GET /api/v1/admin/auth/login` needs no authentication and stores a flow
per request, so it is bounded: 10 per minute per client address (per /64
for IPv6), at most 1000 flows waiting for the IdP at once (then 503), and
the housekeeping loop deletes expired flows and sessions every minute.
`next` must be a path on the control plane: it has to start with a single
`/`, and a backslash, a control character or whitespace anywhere (also
percent-encoded in the path) sends the browser to `/` instead, because
browsers read `/\evil.example` and `/<tab>/evil.example` as
`//evil.example`.

## The admin UI

`web/` is a Svelte 5 + Vite + TypeScript app, built with `make web` into
`internal/control/web/dist` and embedded into `boundgate-control`
(`//go:embed`). Every non-`/api/` path on the admin name serves it (history
fallback to `index.html`, immutable caching for hashed assets, a CSP of
`default-src 'self'`). Without a build the binary answers 503 there and the
API keeps working.

Pages: **Overview** (counts, attention list, active tunnels, recent audit),
**Nodes** (filter by status, drawer with fingerprint, confirm dialog with
kind/roles/prefixes/overlay IP, the sign command with copy, edit grant,
reject, revoke), **Sessions** (end user sessions), **Policies** (list with
plain-English summaries; editor with a **builder** and a raw Cedar mode),
**Logs** (audit streams, flow records, tunnel history with filters),
**Admins** (passkeys with approval, signing keys, API tokens),
**Settings** (overlay pool, snapshot max age, global snapshot).

### The policy builder and sanity check

The builder edits one Cedar policy as *effect* (allow / deny), *who*
(any node, an OIDC group, one user, one node, nodes with a role), *where
to* (anywhere, a network prefix, a node, one host) and two condition lists:
"only when all of these hold" (`when { a && b }`) and "except when any of
these hold" (`unless { c || d }`). Conditions cover port(s), protocol,
destination address/range, SNI and DNS names (matches / present but does
not match / present / absent, generating the `has` guards so no evaluation
errors occur), node kind, hardware-bound key, user session present, user in
group, node role and platform. Each condition can be negated. The generated
Cedar is shown live and highlighted, and the summary sentence tells what
the rule does. Switching to *Cedar* edits the text directly; switching back
parses it if it has the builder's shape, otherwise the policy stays raw
Cedar (hand-written policies with other constructs are still fully
supported).

The **sanity check** panel next to the editor evaluates a sample connection
(from node, destination, port, protocol, optional SNI / DNS name, optional
enforcing node for scoped views) with the real engine against the current
registry state **and the editor's unsaved draft**
(`POST /admin/acl/evaluate` with `draft`). It shows ALLOW/DENY, whether the
draft changes today's outcome, the deciding policies, the user session and
groups of the principal, the owner of the destination and any evaluation
errors with a hint. It re-runs on every change, so an admin sees the effect
of a rule before saving it. `draft_only` evaluates the draft alone.

## Development

```bash
make web              # npm ci + vite build inside the box (14-day cooldown), output embedded
make web-check        # svelte-check
box sh -c 'cd web && npm run dev'   # http://localhost:5173 with /api proxied to the lab (add the origin to admin.origins for passkeys)
```

The Go tests (`internal/control/api/adminauth_test.go`) drive the whole
ceremony with a **software authenticator** (ES256, `none` attestation,
CBOR-encoded COSE key): first passkey with bootstrap token, bootstrap dead
afterwards, CSRF, API tokens, logout and re-login by assertion, a wrong key
for the right credential id, a second admin's pending passkey, approval,
revocation, non-admin refusal, a foreign-browser callback and open-redirect
protection. The lab e2e (step 12) checks the SPA is served, the OIDC admin
login yields an `oidc_only` session that cannot reach the API, the CSRF
header, API tokens and the draft evaluation.

## Risks

See SECURITY.md R51–R60.
