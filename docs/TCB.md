# Trusted Computing Base

The TCB is the code whose failure breaks the security promise ("a copied
secret never authorizes a second device"). Keep it small, boring and
reviewed. Everything outside the TCB may have bugs that cause wrong
*authorization* decisions, but it cannot mint a node identity.

## In the TCB

| Component | Why |
|---|---|
| Go `crypto/tls`, `crypto/x509`, `crypto/ecdsa` | TLS 1.3 handshake, certificate parsing, signatures |
| `github.com/quic-go/quic-go` (+ `http3`) | QUIC transport, TLS integration, HTTP/3 |
| `github.com/quic-go/connect-ip-go` | RFC 9484 capsules and datagrams, assigned-address enforcement |
| `internal/devicekey`, `devicekey/softkey`, `devicekey/tpm2key`, `devicekey/sekey` (with the Swift helper `boundgate-sekey`) | Key generation and signing; the only code touching private key material |
| `internal/devicecert` | Builds the certificate that carries the key |
| `internal/transport` | `parseDeviceCert`, `verifyDevice`, `verifyPinned` (spoke → hub), `serverKeyHash` + pin (node → control plane), `PeerFromTLSState`, `AuthenticatedPeer`, `CloseDevice` (revocation) |
| `internal/registry` lookup path | `Holder.LookupSPKI` and `Holder.Stale`: a stale or wrong answer here admits a wrong node |
| Node revocation path | snapshot diff → `Server.CloseDevice`; loss of own approval → `Holder.Clear` + teardown |
| `internal/node/hub.go` `Accept`/`Serve`, `enforceSessions` + `internal/node/forward` | Packets enter the overlay only from here, after the session check for interactive peers and the source check (and the ACL from M3) |
| `registry.Snapshot.SessionFor` | Answers "does this node have a valid user session"; wrong answer = interactive node admitted without a person |
| `internal/node/ipc` verb set | The local attack surface of the privileged daemon |
| `internal/binding` (+ `golang.org/x/crypto/ssh`) | Canonical binding bytes, SSHSIG framing, signature verification against the pinned admin keys; `VerifyChain` decides which admin key list a node, the control plane and the admin CLI accept (signed chain); `VerifySnapshot` decides which records a node believes |
| Node snapshot intake | `controlclient.Run` → `Node.verifySnapshot` → `Holder.Store`: nothing reaches the holder unverified; own-binding failure clears the holder |
| Pinned files in the node state directory | `admin_trust.json` (the admin key list: pinned once, then only moved along signed links, written before use) and `control.pin` (written once), root-only; replacing them re-roots the node's trust |

* `internal/acl` (M3): builds the Cedar entities from the snapshot and is
  the only caller of the authorizer. A bug that attaches the wrong parents
  (user, group, owner) to an entity changes decisions silently.
* `internal/node/flow` (M3): the verdict cache. A bug here can let a
  packet pass without a decision (wrong key normalization, ICMP-related
  lookup) or keep a flow open after its permit went away.
* `internal/netparse` SNI/DNS parsers (M3): fuzzed; a wrong name only
  affects policies that use names.
* cedar-go (v1.8.0, pinned): the policy language and authorizer.
* `internal/control/api/adminauth.go` + go-webauthn (M4): `resolveAdmin`
  decides who is an admin and at which level; `levelOIDCAllowed` is the
  allow-list for `oidc_only` sessions; the bootstrap-token gate
  (`CountActivePasskeys`) and the passkey status rules (first / self /
  pending) live there. The SPA is outside the TCB: it only talks to the
  API with the same rights as its cookie.

## Explicitly outside the TCB

Control-plane SPA and admin API (including confirm, sign tokens and signer
registration: they gate who *may* sign, the nodes decide what *was* signed),
the control plane's database, OIDC handling (`internal/control/oidc`: a bug
creates a wrong user session for a node whose key is still real), Cedar
policies and the ACL
engine, logs, profile files, the `boundgatectl` CLI (`admin sign` produces
a signature; a wrong one is simply refused), route installation (`netcfg`),
`boundgate-mux` and `internal/mux` (no keys, no TLS termination: it chooses
which server gets a packet, and the servers authenticate as if it were the
network; what it adds is the client address it reports, which feeds logs
and rate limits, never an identity decision).
A compromise there can deny access or grant more network reach than
intended (bounded by what hubs advertise and by the signed roles and
prefixes), but cannot make an unapproved key pass the handshake or make a
node believe an unsigned role.

## Rules

1. `transport.AuthenticatedPeer` has unexported fields and exactly one
   constructor, `PeerFromTLSState`. A test (`TestNoOtherConstructors`, M1.6)
   greps the AST for other constructions.
2. Nothing above transport reads certificates. Layers receive a peer, a
   session and a destination.
3. The ACL API is `Authorize(peer, session, destination) → Decision`. There
   is no `SetAuthenticated`, `SkipVerification` or similar.
4. Authorization only removes capabilities: effective access =
   registry (advertised) ∩ profile ∩ ACL.
5. Transport may downgrade (H3 → TCP for the control channel today, for
   tunnels later); authentication never does. Every fallback still requires
   the device certificate.
6. Enforcement happens on the side that lets traffic into a resource (hub,
   subnet router, exit node; from M7 the receiving endpoint). The sender's
   own checks are never the only ones.
7. Dependencies in the TCB are pinned and updated deliberately, never
   `go get -u`. The `box` dev container enforces a 14-day cooldown on module
   versions (`gocooldown check`).

## The 200 lines to review hardest

`internal/transport/peer.go`, `pin.go` and `controlpin.go` between the raw
TLS certificates and the `AuthenticatedPeer` (or the accepted hub, or the
trusted control plane), `internal/binding/binding.go` (`Parse`, `Matches`,
`Verify`, `VerifySnapshot`) and `sshsig.go`, plus `internal/node/hub.go`
`Accept`/`Serve`. That is where the whole model either holds or doesn't.
