# User login (OIDC)

Device identity (the key) says *which machine*; the user session says
*who is sitting at it*. Interactive nodes need both before a hub admits
them; workloads (servers, routers, hubs) need only the key. The kind is
granted by an admin and part of the signed binding, so the control plane
cannot silently turn a laptop into a "workload" that needs no login.

## Flow

```
boundgatectl login
  node ──POST /node/login/start (mTLS)──▶ control plane: login_flow {state, nonce, PKCE}
  node ◀── {flow_id, url} ──────────────  url = IdP authorize URL
  prints the URL (opens no browser itself)
user's browser ──▶ IdP (Authentik): authenticate, consent
IdP ──302──▶ https://control.example/api/v1/oidc/callback?code&state   (admin name, WebPKI)
  control plane: state → flow → node; code + PKCE verifier → tokens;
  ID token verified (signature, issuer, audience, expiry, nonce);
  identity kept on the flow (status confirm), nothing signed in yet
browser ◀── "Sign in this device?": device name, hostname, platform,
            approved since, key fingerprint, the warning, two buttons
user presses "Sign in this device" ──POST /api/v1/oidc/confirm (single-use token)──▶
  user_session {node, subject, email, username, groups, expires_at};
  snapshot++
node polls GET /node/login/{flow} ──▶ "pending" until the button, then "done" + session (no token)
every node's snapshot carries the session; hubs admit node-a
```

### Why the browser has to confirm the device

Nothing ties the browser that signs in at the IdP to the device that
started the login: the login URL is just a link. Whoever controls an
approved node could start a login, send the link to a colleague ("please
sign in here"), and, since an IdP with a running session usually signs a
person in without a prompt, receive that colleague's identity and groups on
their own device. So the callback only asks. The page names the device
that is about to be signed in (name, hostname, platform, when it was
approved, the start of its key fingerprint, the same one `boundgatectl
status` and the apps show) and says plainly: *Only continue if you started
this sign-in on this device yourself. Whoever holds this device gets your
access.* The login counts only when the person presses **Sign in this
device**; **Cancel** fails the flow, and the node reports the login as
failed.

The control plane also compares the address the node started the flow
from with the address the browser comes back from (the same /64 counts as
the same for IPv6). When they differ the page adds a stronger warning with
both addresses. It does not refuse: a phone on mobile data, IPv6 next to
IPv4 or a VPN on the laptop all give legitimate differences.

The button posts a single-use token bound to the flow (only its hash is
stored), valid for five minutes and at most until the flow expires; a
page on another site cannot know it, and the page cannot be framed. Both
the question (`login awaiting confirmation`, with the two addresses) and
the answer (`login completed` or `login cancelled`) are in the user-auth
log. What remains is a person who confirms despite the warning: the page
can make the question impossible to miss, not answer it for them (R120).

A node keeps at most three login flows open (a fourth fails the oldest)
and at most two status requests waiting at once (429 beyond that).

* The node never sees a token. The session is a row in the control plane
  and a record in snapshots. Revoking it (admin, logout, expiry) bumps the
  snapshot; hubs close the node's tunnels within one long-poll round trip.
* Hubs also enforce expiry themselves every 10 s from the `expires_at` in
  the snapshot, so a session cannot outlive its lifetime when the control
  plane is unreachable. A stale snapshot (`max_age`) admits nobody anyway.
* One active session per node; a new login replaces the old one. The
  session lifetime is a control-plane setting (`oidc.session_lifetime`,
  default 24 h); no refresh tokens, no silent renewal. Log in again.
* The login URL host gets a bypass route while the overlay is up, so a
  full-tunnel profile does not swallow the login.
* The callback page and its confirmation are served on the admin name
  without admin authentication (and from outside `admin_allow`): the
  `state` binds the callback to a flow a node started, the code is single
  use, PKCE binds it to the control plane, the nonce binds the ID token to
  the flow, and the confirmation token binds the button to the page the
  callback showed. Flows expire after 10 minutes.

`boundgatectl status` shows the user (`user: martin [vpn-users] until …`)
or `LOGIN REQUIRED` when a hub refused the node.

## Enforcement

The hub checks the session in `Accept` (before the tunnel exists) and
whenever a snapshot arrives or the 10 s timer fires (`enforceSessions`):
an interactive peer without a valid session gets its tunnels closed with
`ErrCodeSessionExpired`. The spoke shows `login required` and retries with
a bounded backoff; when its own session appears in its snapshot, it redials
immediately.

Subnet routers do not enforce sessions: they see packets from the hub
tunnel, not per-peer identities. Enforcement is the hub's job (and, from
M3, the ACL's, which gets the session's user and groups per flow).

## Authentik

1. **Provider**: OAuth2/OpenID, confidential client, authorization code,
   redirect URI `https://control.example/api/v1/oidc/callback`, signing key
   any RS256 certificate, scopes `openid profile email` plus a **groups**
   scope mapping (Authentik does not emit `groups` by default: create a
   scope mapping with scope name `groups` and expression
   `return {"groups": [g.name for g in request.user.ak_groups.all()]}`,
   attach it to the provider).
2. **Application** bound to the provider; restrict access to the groups
   that may use the VPN.
3. Control plane configuration:

   ```yaml
   oidc:
     issuer: https://auth.example.com/application/o/boundgate/
     client_id: …
     client_secret_file: /var/lib/boundgate/oidc.secret     # or client_secret
     redirect_url: https://control.example/api/v1/oidc/callback
     scopes: [openid, profile, email, groups]                 # default
     groups_claim: groups                                     # default
     session_lifetime: 24h                                    # default
   ```

   Discovery runs on the first login (the control plane starts without the
   IdP); a failing IdP makes `login/start` answer 502.

Claims used: `sub` (subject, the stable identity), `email`,
`email_verified`, `preferred_username` (fallback `name`), `groups`.
Nothing else is stored.

* `email` is dropped (stored empty) when the token says
  `email_verified: false` (also the string `"false"`): a user who can type
  an address into their IdP profile must not match a policy on someone
  else's address. When the claim is absent the email is taken as the IdP
  sends it; configure the IdP to send only addresses it controls.
* `username` is the IdP's `preferred_username`, which in many IdPs
  (Authentik included) **the user can change** in their own profile. It is
  shown in the UI and logs for people to read; a policy should decide by
  `subject` or by groups (`principal in BoundGate::Group::"…"`), not by
  `username` (ACL.md).
* `groups` is de-duplicated, in the IdP's order.

The same provider and redirect URI serve **admin logins** (M4): members of
`admin.group` (default `admins`) get an admin session that still needs a
passkey; see ADMIN-AUTH.md. Put the administrators into that Authentik
group and let the application's access policy include it.

## Development lab

`boundgate-fakeidp` (service `idp`, image of the control plane) is a tiny
OpenID provider that logs in the configured user `martin` with groups
`vpn-users, admins` without asking. `./setup-dev.sh login node-a` plays the
browser: it follows the IdP redirect inside the lab network and calls the
callback on the Mac side (`http://localhost:18080`, the lab devproxy; see
ADMIN-AUTH.md). The fake IdP's issuer is `http://idp.localhost:19000`: a
Docker DNS alias inside the lab, and on the Mac the published loopback port
(browsers and curl map `*.localhost` to loopback), so a real browser on
the Mac can complete both user logins (`boundgatectl login` prints the URL)
and admin logins (the UI's "Sign in with SSO") with one click and no
password.
