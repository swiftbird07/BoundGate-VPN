# Enrollment

Every node is approved by a person, twice: an administrator confirms the
request after comparing the key fingerprint out of band, and an
administrator's own hardware key signs the resulting binding. There are no
enrollment tokens and no self-service paths. The control plane records what
a node claims and distributes what admins decided and signed.

## Flow

```
node                          control plane                         admin
----                          -------------                         -----
boundgatectl enroll
  key exists? else create
  self-signed cert
  pins the control key   ──▶  TLS handshake proves key possession
  (first use, or config)      parseDeviceCert: P-256, self-signed, not CA
  POST /api/v1/node/enroll    UnverifiedSPKI -> pending row
  claims: name, platform,     rate limit 5/min per source IP
  key kind, requested         503 while no admin key is registered
  roles/prefixes, public addr
  ◀── 202 pending, fingerprint, admin signer keys, control key hash
  pins the admin keys (once)
prints fingerprint ────────────────────────────────────────────▶  compares with
                                                                  "Pending nodes"
                              POST /admin/nodes/{id}/confirm  ◀── grant: roles, prefixes,
                              (fingerprint echoed)                overlay ip, public addr
                              status = confirmed, overlay ip
                              assigned, sign token (10 min)
                              ──▶ sign_command                ──▶ runs it where the
                                                                  YubiKey is plugged in
                              GET /sign/binding (token)       ◀── CLI checks the fingerprint
                                                                  it was given, signs (touch)
                              POST /sign/signature (token)    ◀── SSHSIG
                              verify vs admin keys, token used,
                              status = approved, snapshot++
every node long-polls  ◀───── snapshot with the new peer + its binding + signature
                              every node verifies the binding against its pinned admin keys
boundgatectl up               (hubs accept it, spokes dial it if it is a hub)
```

* The enrollment request carries only claims: name, hostname, platform,
  key kind, `hardware_bound`, requested roles and prefixes, public address.
  None of them is verified. The one thing that is proven is possession of
  the key whose hash becomes the identity.
* The **grant** is the admin's decision and is stored separately from the
  request. Roles are required; prefixes need the `subnet-router` or
  `exit-node` role; the overlay address is assigned automatically unless
  given; `public_addr` is what peers dial (hubs, and spokes with a direct
  path) and only an admin's value counts: the node's is shown as a request.
  Prefixes must not overlap the overlay pool (a default route may). The
  **kind** is `interactive` (default: a person must log in before hubs
  admit the node, `docs/OIDC.md`) or `workload` (servers, routers, hubs).
* The **binding** (`node_id, spki, key_version, roles, prefixes,
  overlay_ip`) is what gets signed. See `BINDINGS.md`.
* A known key that enrolls again learns its current status instead of
  creating a second request (idempotent). Revoked keys stay revoked
  forever; a revoked node needs a new key (`rm device.key device.crt`)
  and a new approval.
* Pending requests expire after `pending_ttl` (default 24 h). Sign tokens
  expire after 10 minutes; `confirm` again (no body needed) mints a new one.
* The confirm call accepts an optional `fingerprint`. The UI sends what
  the admin confirmed on screen so a stale page cannot confirm a different
  request. A mismatch is a 409. The CLI sign step checks the fingerprint a
  second time, independently, against what the admin typed.

## What the user must do at the first contact

A device that has never talked to this control plane shows the key the
control plane presents and asks before it pins it:

```
This node has not talked to this control plane before. It presents the key

  5c1f aa42 0702 4bc8 …

Compare it with the fingerprint your administrator gave you (admin UI, Nodes page).
Pin this key? Type yes:
```

The Mac app shows the same with "It matches: trust this key and request
access". The administrator reads the fingerprint from the top of the Nodes
page in the admin UI (`GET /api/v1/admin/identity`) and gives it to the user
over a channel they trust - the same channel, the other direction, as the
device fingerprint below. Until a key is pinned the node refuses the control
plane at its certificate and sends nothing of its own. Without a terminal
(scripts, `-json`): `boundgatectl enroll -pin '<fingerprint>'`, or
`-accept-new-pin` to pin unseen (the lab does; then it is plain trust on
first use). A pin provisioned in the configuration (`control.pin`) skips all
of this.

## What the admin must do

1. Ask the user for the fingerprint shown by `boundgatectl enroll` (or
   `boundgatectl identity`). Use a channel you trust for that user: in
   person, a video call, a signed message.
2. Compare it with the fingerprint in the pending list. All 64 hex digits.
3. Check that the claimed platform and key kind make sense for the device
   in front of you. A software key (`softkey`) can be copied by whoever reads
   the node's state directory: approve it only for development or if policy
   allows it. A node that "reports a hardware key" (`tpm2`, a Mac's
   `secure-enclave`) gets
   `hardware_bound` with your confirmation unless you untick it; the report
   is not proven remotely, so grant it for machines you know, and think
   twice for VMs on a hypervisor others administer (TPM.md).
4. Decide the grant. Kind: `interactive` for a laptop or desktop someone
   logs in on, `workload` for machines nobody sits at (they never need a
   user session; grant it only to machines you operate). Roles: an
   `endpoint` reaches things; a
   `subnet-router` brings a network with it (grant only the prefixes you
   expect, with `routed` where the LAN can route back to the pool and
   `snat` otherwise); a `hub` sees the overlay traffic of everyone who uses
   it (grant only to machines you operate); an `exit-node` is a router for
   `0.0.0.0/0`.
5. Confirm. Optionally set a better name. Copy the sign command.
6. On the machine with your security key, run the sign command with the
   fingerprint you compared. Read what the CLI prints (name, roles,
   prefixes, overlay address), touch the key. The node is approved when the
   command says so.

Everything is written to the `enrollment` log stream (file and database):
request with source IP and claims, confirmation with admin subject and
grant, approval with the signing key's fingerprint, rejected signatures,
revocation.

## Changing a grant

`PATCH /api/v1/admin/nodes/{id}` changes name, kind, roles, prefixes,
overlay address or public address. A change to a **signed** field (kind,
roles, prefixes, overlay address) invalidates the signature: the node goes back to
`confirmed`, every peer closes its tunnels with it at once, the node itself
loses its snapshot and goes down, and the response carries a new sign
command. After the signature it comes back (an `auto_up` node on its own,
an endpoint with `boundgatectl up`). A rename or a new public address keeps
the approval and only bumps the snapshot.

## Revocation

`DELETE /api/v1/admin/nodes/{id}` marks the node revoked, frees its overlay
address and bumps the snapshot. Every hub closes the node's live tunnels
with QUIC error `ErrCodeRevoked` within one long-poll round trip (measured
~7 ms) and refuses the next handshake. The node's next snapshot request
gets 403; it forgets its snapshot, tears the overlay down and refuses
`boundgatectl up` until approved again (which needs a new key).

## Admin signing keys

The list of admin keys is a signed chain (`BINDINGS.md`): adding or removing
a key is a proposal that a key of the current list has to sign.

```
POST   /api/v1/admin/signers {name, public_key}   -> 202, sign_command
DELETE /api/v1/admin/signers/{id}                 -> 202, sign_command
boundgatectl admin sign-signers --control https://bg.example.com --token bgsigners_…
```

The first key signs the first list itself (`sk-ssh-ed25519@openssh.com` from
a YubiKey is the intended kind; `ssh-ed25519` for development). Nodes pin
the signed list at enrollment and afterwards follow only changes signed by
a key of the list they hold, so keys can be added and removed at any time
without re-enrolling. With no signed list, enrollment and confirmation are
refused.
