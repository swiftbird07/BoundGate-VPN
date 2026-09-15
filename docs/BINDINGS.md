# Signed bindings

A **binding** is the statement an administrator signs for every node:

```json
{"node_id":"f11a…","spki":"cb0d…","key_version":1,
 "roles":["endpoint","subnet-router"],
 "prefixes":[{"prefix":"192.168.178.0/24","mode":"snat"}],
 "overlay_ip":"10.21.0.4"}
```

It says: *this node id and this device key hold these roles, may announce
these prefixes, and own this overlay address*. Every node verifies the
bindings of its peers and of itself against the admin keys it pinned at
its own enrollment. The control plane distributes bindings but cannot
create or change one. A compromised control plane can therefore still
delete nodes (deny service) and change unsigned fields, but it cannot
invent a node, turn an endpoint into a hub, or widen a router's prefixes.

## Why SSHSIG and an SSH key

* Administrators already own hardware keys that speak SSH: a YubiKey with
  a FIDO2 resident key (`ssh-keygen -t ed25519-sk`). The same key signs
  bindings, with a touch per signature.
* SSHSIG (`ssh-keygen -Y sign`) is a small, documented format
  (`PROTOCOL.sshsig` in OpenSSH) with a namespace that prevents a
  signature made for one purpose from being replayed for another. BoundGate
  uses the namespace `boundgate-binding`.
* `golang.org/x/crypto/ssh` does the cryptography, including sk-keys (it
  checks the user-presence flag). BoundGate implements only the framing,
  which is pinned to OpenSSH by a test vector: signing the vector message
  with the vector ed25519 key must reproduce `ssh-keygen`'s signature byte
  for byte, and `ssh-keygen -Y verify` accepts what BoundGate produces.

Accepted key types: `sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com` (hardware), `ssh-ed25519`,
`ecdsa-sha2-nistp256` (software; development, or an HSM-backed agent). No
RSA, no DSA, no certificates.

## Canonical form

The signed bytes are compact JSON with the fields in exactly the order
above, roles sorted and de-duplicated, prefixes masked and sorted by
prefix then mode, no whitespace, no HTML escaping. A verifier re-encodes
what it parsed and refuses anything that does not reproduce the bytes
(unknown fields, other order, spacing). `binding.Parse` and
`binding.(Binding).Canonical` in `internal/binding` are the only
implementations.

Not signed: the name, the public address of a hub, platform, key kind and
`hardware_bound`. A wrong public address only fails the pinned handshake;
the others are claims shown to admins.

`key_version` counts re-keys of the same node id (always 1 for now); a
future key rotation will sign a new binding with `key_version + 1`.

## Lifecycle

```
pending ──confirm──▶ confirmed ──sign──▶ approved ──revoke──▶ revoked
   ▲                    │  ▲                │
   └─ reject (delete) ──┘  └── PATCH of a signed field (roles, prefixes, overlay ip)
```

1. **confirm** (admin session, fingerprint compared): the grant is stored,
   the overlay address assigned, and a **sign token** minted: 10 minutes,
   single use, bound to the node id and its key hash. The response carries
   the command to run:

   ```
   boundgatectl admin sign --control https://control.example --node <id> --fingerprint <spki> --token bgsign_…
   ```

   A confirmed node is not in any snapshot. Its `up` fails.
2. **sign** (on the machine with the key): the CLI fetches the canonical
   binding with the token, refuses if the fingerprint the admin typed does
   not match, signs (ssh-agent, key file, or a signature file made with
   `ssh-keygen -Y sign`), verifies the result locally against the
   registered admin keys and posts it. The control plane verifies again
   against its active signers, requires the signature to be over the
   *current* grant (a grant changed after the token was minted fails with
   409), marks the token used and moves the node to `approved` in the same
   transaction. Every node receives the record with `binding` and
   `signature` in its next snapshot.
3. **PATCH** of roles, prefixes or overlay address on an approved node
   drops the signature: the node goes back to `confirmed`, leaves every
   snapshot at once (hubs close its tunnels, its own poll gets 403), and
   the response carries a new sign command. A rename or a new public
   address keeps the approval.
4. **revoke** deletes the node from snapshots; the row stays for audit.

## What nodes verify

On every snapshot, before it is installed (`internal/node`
`verifySnapshot` → `binding.VerifySnapshot`):

* **Self**: the node's own record must carry a binding whose signature
  verifies against a pinned admin key and whose content equals the record
  (node id, key, key version, roles, prefixes, overlay address). If not, the
  snapshot is refused, the holder is cleared (the hub admits nobody), the
  overlay goes down, and `boundgatectl status` shows
  `binding: INVALID: …`. An `auto_up` node comes back on its own once a
  valid snapshot arrives.
* **Peers**: every peer with an invalid or missing binding is dropped from
  the snapshot before it is indexed. A hub therefore closes that peer's
  tunnels and refuses its handshake; a spoke does not dial it. Dropped
  peers are listed as `ignored_peers` in the status and logged.

The lab demonstrates this with `sqlite3`: adding `hub` to a router's roles
in the control plane database makes every other node ignore that router
within one long-poll round, and the router itself goes down because its own
binding no longer verifies.

## Admin keys on nodes

The enrollment response carries the active admin signer keys
(authorized_keys lines). The node stores them in `state_dir/admin_keys`
**once** and never updates them: the set of keys a node trusts is fixed at
enrollment. Consequences, decided deliberately:

* A key registered later can sign bindings, but nodes enrolled before it
  will not accept them. Register all admin keys before enrolling nodes, or
  re-enroll nodes when a key is added.
* Revoking a key at the control plane stops it from signing *new*
  bindings; nodes keep trusting it for the bindings they hold. Rotating
  out a compromised admin key means re-enrolling every node.
* Losing every admin key means re-enrolling every node.
* The first delivery is trust-on-first-use over the pinned control-plane
  channel (see below). An enterprise provisions `admin_keys` by
  configuration management before the first start; the file is then
  authoritative and the delivered list is ignored.

Enrollment is refused (503) while no admin key is registered, so no node
ever pins an empty set.

## Control-plane pin

The node channel does not use WebPKI. Nodes pin the SPKI hash of the
control plane's long-lived node-channel key (`nodes.crt`), like an SSH host
key: the first connection learns it and stores it in `state_dir/control.pin`
(logged with a warning and shown by `boundgatectl identity`); `control.pin`
in the node configuration provisions it instead. Any other key afterwards
fails the handshake with `control plane key does not match the pinned key`
and the node keeps refusing until an operator removes the pin file or
updates the configuration. The control plane also reports its key hash in
the enrollment response; a mismatch with the pin is logged as an error
(a consistency check, not a source of trust).

Rotating the node-channel key therefore means re-pinning every node.

## Development

`make setup-dev` creates a software ed25519 key inside the control
container (`state/control/admin_signer`), registers it, and signs with
`boundgatectl admin sign --key`. With a real YubiKey:

```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "martin yubikey" -f ~/.ssh/id_boundgate_sk
./setup-dev.sh api POST /api/v1/admin/signers "$(jq -cn --arg k "$(cat ~/.ssh/id_boundgate_sk.pub)" '{name:"martin yubikey",public_key:$k}')"
ssh-add -K                           # load the resident key into ssh-agent
boundgatectl admin sign --control https://127.0.0.1:18443 --cacert deploy/compose/state/control/control.crt --node … --fingerprint … --token …
```

or without an agent: `--out binding.json`, then `ssh-keygen -Y sign -n
boundgate-binding -f ~/.ssh/id_boundgate_sk binding.json`, then
`--signature binding.json.sig`.
