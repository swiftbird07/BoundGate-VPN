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
  user_session {node, subject, email, username, groups, expires_at};
  snapshot++
node polls GET /node/login/{flow} ──▶ "done" + session (no token)
every node's snapshot carries the session; hubs admit node-a
```

* The node never sees a token. The session is a row in the control plane
  and a record in snapshots. Revoking it (admin, logout, expiry) bumps the
  snapshot; hubs close the node's tunnels within one long-poll round trip.
* Hubs also enforce expiry themselves every 10 s from the `expires_at` in
  the snapshot, so a session cannot outlive its lifetime when the control
  plane is unreachable. A stale snapshot (`max_age`) admits nobody anyway.
* One active session per node; a new login replaces the old one. The
  session lifetime is a control-plane setting (`oidc.session_lifetime`,
  default 10 h); no refresh tokens, no silent renewal. Log in again.
* The login URL host gets a bypass route while the overlay is up, so a
  full-tunnel profile does not swallow the login.
* The callback page is served on the admin name without admin
  authentication: the `state` binds it to a flow a node started, the code
  is single use, PKCE binds it to the control plane, the nonce binds the
  ID token to the flow. Flows expire after 10 minutes.

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
     session_lifetime: 10h                                    # default
   ```

   Discovery runs on the first login (the control plane starts without the
   IdP); a failing IdP makes `login/start` answer 502.

Claims used: `sub` (subject, the stable identity), `email`,
`preferred_username` (fallback `name`), `groups`. Nothing else is stored.

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
