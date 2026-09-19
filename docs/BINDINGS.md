# Signed bindings

A **binding** is the statement an administrator signs for every node:

```json
{"node_id":"f11a…","spki":"cb0d…","key_version":1,"kind":"interactive",
 "roles":["endpoint","subnet-router"],
 "prefixes":[{"prefix":"192.168.178.0/24","mode":"snat"}],
 "overlay_ip":"10.21.0.4"}
```

It says: *this node id and this device key are of this kind (interactive:
a person must log in; workload: the key alone suffices), hold these roles,
may announce these prefixes, and own this overlay address*. A binding for a
node whose key an admin accepted as living in a TPM ends with
`,"hardware_bound":true}` (TPM.md). Every node verifies the
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

`hardware_bound` is the last field and is **left out when false**. Bindings
signed before the field existed therefore stay valid and mean what they
meant: not hardware-bound. An explicit `"hardware_bound":false` is not
canonical and is refused.

Not signed: the name, the public address of a hub, platform, key kind and
what the node itself reported about its key (`hardware_claimed`). A wrong
public address only fails the pinned handshake; the others are claims
shown to admins.

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
3. **PATCH** of kind, roles, prefixes or overlay address on an approved node
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

## The admin key list is signed too

Which keys may sign bindings is itself a signed statement: a versioned list,
every version signed by a key of the version before it
(`internal/binding/signerset.go`, SSHSIG namespace `boundgate-signers`).

```
set 1 (genesis)  keys {A}      signed by A    a node pins it at enrollment
set 2            keys {A, B}   signed by A    A adds B
set 3            keys {B}      signed by B    B removes A
```

```json
{"type":"boundgate-signer-set","version":3,"prev":"<sha256 of set 2>","keys":["sk-ssh-ed25519@openssh.com AAAA..."]}
```

Administrators can therefore add and remove keys **without re-enrolling any
node**, and only they can: the control plane stores the chain and forwards
it with the enrollment status and every snapshot, but it holds no admin key.
A node (`state_dir/admin_trust.json`) accepts a new list only if

* its version is exactly the pinned version + 1 and `prev` is the hash of
  the pinned set (no gaps, no forks, no list from another deployment),
* the signature verifies, in the `boundgate-signers` namespace, against a
  key of the **pinned** set. A key that only the new set contains cannot
  sign it, and a binding signature can never stand in for it,
* the set is canonical (one hash per set), has a constant `type`, holds 1
  to 32 keys of the allowed types, sorted and unique. The list can never
  become empty.

Anything else changes nothing: verification is all-or-nothing, the node
keeps its list, reports `admin list: REFUSED …` in `boundgatectl status`
and logs the reason. A version at or below the pinned one must be
byte-identical to what the node has (rollback = refused). The new list is
written to disk (fsync, rename) before it is used; a damaged trust file is
an error, never a reason to pin again.

Consequences:

* **Adding a key**: propose it in the UI (Admins → Admin signing keys) or
  `POST /api/v1/admin/signers`, run the printed `boundgatectl admin
  sign-signers --control … --token …` with a key of the current list. Nodes
  follow with their next snapshot (seconds).
* **Removing a key** works the same way and is final for every node that
  saw it: the key can no longer sign lists **or bindings**. Nodes whose
  binding was signed by it go back to `confirmed` and need a new signature
  (the proposal lists them). To rotate without a gap, re-sign those nodes
  with another key first.
* **The first list** is signed by one of its own keys. A node without a pin
  takes the list of its first contact (trust on first use over the pinned
  control-plane channel, R24) or, provisioned with `control.signers_genesis:
  <hash>` (shown in the UI), only a chain that starts with exactly that set.
* Losing **every** key of the current list still means re-enrolling every
  node (R23). Keep at least two keys in the list.
* What this cannot do: a node that never receives a removal (offline, or a
  control plane that withholds it) keeps trusting the removed key. Together
  with that key an attacker could fork the list for such nodes (R83).

`boundgatectl admin sign-signers` trusts the control plane with nothing: it
verifies the chain itself, checks that the proposal continues it, prints the
resulting list (keep / ADD / DROP with fingerprints) from the very bytes it
signs, asks for `yes`, verifies its own signature the way a node will, and
keeps its own pin of the list per control plane
(`~/.config/boundgate/signers/<host>.json`), so a control plane that shows
another history to obtain a signature on a fork is caught on the admin's
machine.

Nodes that pinned a plain key list before lists were signed (`admin_keys`)
refuse to start with an explanation; remove the file to pin the signed list
or re-enroll. Enrollment is refused (503) while no signed list exists, so no
node ever pins an empty set.

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
