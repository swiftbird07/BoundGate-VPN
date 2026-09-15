# Security: threat model and risk register

Living document. Every milestone updates the register.

## Assets

* Node identity keys (in hardware; softkey only for development).
* The registry: which keys are approved with which roles and prefixes,
  which sessions exist.
* The networks behind hubs, subnet routers and exit nodes, and the overlay
  itself (node-to-node reachability).
* Flow logs (contain user, node, destination data).

## Threat model

### What we defend against

| Threat | Defense |
|---|---|
| Copy of the node's state directory to another machine | Key is non-exportable (TPM/SE); with softkey this is **not** defended, softkey is dev-only and reported as `hardware_bound=false` for policy |
| Stolen OIDC tokens or session cookies | Sessions are bound to the node's SPKI in the control plane and only ever travel inside snapshots; a hub accepts them together with the node's mTLS connection (M2) |
| Unknown node connecting to a hub | Registry lookup inside the TLS handshake; nothing above TLS exists for unapproved keys |
| Fake hub (anyone with the public address) | The spoke pins the hub's SPKI from the snapshot; a hub is a node whose key carries an admin-signed binding with the hub role |
| Control plane promotes a node to hub or widens a router's prefixes (bug or compromise) | Roles, prefixes and overlay address are in the signed binding; a record that differs from its binding is ignored by every node (tested in the lab with a direct database edit) |
| Fake control plane (DNS, rogue CA in the system store) | The node channel pins the control plane's own key, not WebPKI; a different key is refused until an operator re-pins |
| Admin session hijacked (bootstrap token, later cookie) | Can confirm and mint sign tokens, but not approve: the signature needs the admin's hardware key. The sign step re-checks the fingerprint the admin typed |
| Node revoked while up | Every hub closes its tunnels on the snapshot diff (measured: ~7 ms); reconnect fails at the handshake; the node itself loses its snapshot and tears down |
| Spoofed source addresses inside a tunnel | Hubs drop packets whose source is neither the node's overlay address nor one of its granted prefixes; connect-ip-go enforces assigned addresses on both ends |
| A node announcing networks it was not granted | Prefixes are granted by an admin and only then assigned; requested prefixes are shown as claims |
| Profile asking for more networks than allowed | Effective routes = profile ∩ advertised; hubs also enforce the ACL per flow (M3) |
| Control plane unreachable for long | Snapshots carry `max_age_seconds`; a stale snapshot admits nobody (fail closed) |
| Policy-layer bug (ACL, OIDC, SPA) | Cannot mint identity; bounded by the TCB rules in `TCB.md` |
| Replay of connection setup | 0-RTT disabled, session tickets disabled |

### What we do not defend against (accepted, documented)

| Limitation | Notes |
|---|---|
| Root on the enrolled node while it is enrolled | Root can use the TPM as a signing oracle and the machine as a proxy. The key cannot be extracted; access ends with revocation. |
| Enrollment of a software key on a device that has a TPM | No attestation in the prototype. The admin approves after comparing the fingerprint out of band and is expected to know the device. `hardware_bound` is what the node reports, not proven, and not part of the binding. |
| First contact of a node with the control plane | Trust on first use for the control-plane key and the admin key list, over that channel. An attacker on path during the very first connection can substitute both. Enterprise: provision `control.pin` and `admin_keys` by configuration; small deployments: compare the fingerprints the node logs. |
| Admin keys are fixed at enrollment | A key added later cannot sign for older nodes; a compromised admin key keeps verifying on nodes that pinned it. Both mean re-enrolling nodes. Chosen over an updatable list because an updatable list would again be something the control plane controls. |
| Compromise of a hub | The hub terminates tunnels and sees overlay packets between spokes by design (M7 adds end-to-end paths). Its role is admin-granted. |
| Compromise of a subnet router | Its LAN is exposed to the overlay as granted; the LAN itself is not BoundGate-authenticated (an Apple TV has no key). |
| Compromise of the control plane | Can delete nodes (deny service), change unsigned fields (name, hub public address), policy (M3) and sessions (M2), and route traffic through a chosen *approved* hub. Cannot forge a device key, invent a node, change roles or prefixes, or move an overlay address: those are in the admin-signed binding that every node verifies against keys pinned at enrollment (`BINDINGS.md`). Cannot impersonate the control plane to enrolled nodes either (pinned key). |
| TPM firmware vulnerabilities | Out of scope; re-enroll all nodes if one becomes known. |

## Risk register

| # | Risk | Status | Mitigation / decision |
|---|---|---|---|
| R1 | connect-ip-go is pre-1.0 (v0.2.0 pinned, v0.3.0 blocked by cooldown until 2026-09-22) | open | All use isolated in `internal/transport`; `Tunnel` wrapper; pin exact versions |
| R2 | http3 exposes the QUIC connection only via `ConnContext` | verified M0 | `ConnContext` runs after the handshake; `PeerFromTLSState` re-verifies per request |
| R3 | Enroll endpoint is reachable without approval | mitigated M1 | Creates `pending` rows only; rate limit per source IP; expiry 24 h; fingerprint shown prominently |
| R4 | Admin approves without comparing the fingerprint | partly M1 | API takes the confirmed fingerprint and refuses mismatches; UI (M4) will require it; procedure in ENROLLMENT.md |
| R5 | Cedar schema validator is experimental | planned M3 | Validate = parse + dry-run; schema check advisory |
| R6 | MTU/fragmentation over QUIC datagrams | open | TUN MTU 1280 both ends; ICMP "packet too big" from `WritePacket` is forwarded back |
| R7 | Colima kernel features (tun, nftables, ip_forward) | verified M0 | Works on kernel 6.8 in Colima |
| R8 | Bypass routes go stale when hub/control/IdP IPs change | open | Re-resolved on every dial; DNS changes mid-session are not tracked |
| R9 | macOS node needs root for utun and modifies `scutil` DNS | M5 | launchd daemon, state file, cleanup on next start |
| R10 | Secure Enclave cannot be used from a launchd daemon | design | User-context helper process signs on behalf of the daemon over local IPC (post-prototype) |
| R11 | Authentik `groups` claim needs a scope mapping | M2 | Documented configuration; mockoidc for CI |
| R12 | Loss of the only admin passkey | M4 | Bootstrap-token rotation via CLI on the control-plane host |
| R13 | Nodes shell out to `ip`/`nft` | accepted | Small, auditable commands in the system log; netlink later if needed |
| R14 | Softkey used in production | policy | `hardware_bound=false` visible in registry, UI and ACL context; policies should require `hardware_bound` |
| R15 | Chat exports in the repo directory contain ChatGPT session tokens | mitigated | `*.webarchive` and the HTML export are in `.gitignore`; never commit |
| R16 | Registry file replaced atomically is invisible through a single-file bind mount | closed M1.5 | The standalone registry file no longer exists; nodes always use the control plane |
| R17 | `go test -race` unavailable in the dev container (no cgo/gcc) | fixed M0 | gcc added to the box image; `make test-race` |
| R18 | Admin API with a bearer token | accepted dev | Now TLS on 443 (self-signed in dev, WebPKI in production), bound to 127.0.0.1:18443 in compose; M4 replaces the token with OIDC + passkey sessions |
| R19 | Nodes trust the control plane's node-channel certificate from a shared file | closed M1.6 | Nodes pin the SPKI (TOFU into `control.pin`, or `control.pin` in the config); a changed key is refused (tested in e2e) |
| R20 | Gateway token file on disk | closed M1.5 | Gateways are nodes; the node channel is authenticated by the device certificate, there is no token |
| R21 | Hubs terminate tunnels and see overlay traffic | accepted | Hub role granted by an admin (signed in M1.6); payloads are mostly TLS anyway; end-to-end paths in M7 |
| R22 | Verifier bug: a wrong SPKI or binding accepted | mitigated M1.6 | One implementation each in `transport` (`verifyDevice`, `verifyPinned`, `serverKeyHash`) and `binding` (`Parse`, `Matches`, `Verify`); negative tests (tampered field, foreign signer, copied signature, sk/software key confusion, non-canonical JSON), fuzzers for the SSHSIG and binding parsers; AST test for foreign constructors still open |
| R23 | Loss of all admin signing keys | documented | Several keys from the start, any one signs; losing all means re-enrolling every node (`BINDINGS.md`) |
| R24 | Admin signing keys are delivered to nodes at enrollment by the control plane | accepted | TOFU over the pinned channel, once, never updated; enterprise provisions `admin_keys`; enrollment refused while no key exists so nobody pins an empty set |
| R25 | Routed mode without a return route in the LAN; overlapping home networks | documented | Mode per prefix, `snat` as fallback; Fritz!Box static routes documented in DEV.md; 1:1 NAT later |
| R26 | Snapshot too old when the control plane is down | mitigated M1.5 | `max_age_seconds` (default 24 h) then fail closed; `Holder.Stale` in the handshake lookup |
| R27 | SSHSIG framing implemented by us | mitigated M1.6 | Format from OpenSSH PROTOCOL.sshsig; test vector made with `ssh-keygen -Y sign`, and our ed25519 signature over it is byte-identical to ssh-keygen's; signature algorithm pinned to the key type; x/crypto/ssh verifies (incl. sk user-presence flag) |
| R28 | One-time token for the CLI signing step | mitigated M1.6 | 10 min, hash stored, bound to node id and key hash, marked used in the approving transaction (reuse = 409, tested), older unused tokens of the node invalidated, rate limited, audited; the token travels in the confirm response and in a shell command line (history), acceptable for a 10-minute single-use secret |
| R29 | Admin and node traffic share port 443 | mitigated M1.5 | SNI decides the TLS configuration; the node name requires a client certificate, the admin name never does; tested (`TestSNISplit`) |
| R30 | A spoke hangs on several hubs; asymmetric paths | accepted | One primary per spoke for all destinations, hub addresses via their own link; switch only when the tunnel ends; hubs do not forward for each other (a spoke connected to only one hub can be unreachable through the other) |
| R31 | Hub crash (not graceful stop) is noticed only after the QUIC idle timeout | accepted | Idle timeout 30 s, keepalive 10 s on tunnels; graceful stop closes tunnels immediately (measured failover 0 s) |
| R32 | Node-channel HTTP/3 falls back to TCP on any dial error | accepted | Same TLS identity and SNI on both; fallback is logged and retried on H3 every 5 min |
| R33 | Signed binding does not cover name, public address, `hardware_bound` | accepted | Name and address are not security-relevant (a wrong hub address fails the pinned handshake); `hardware_bound` is a claim anyway (no attestation); policies must not treat it as proven |
| R34 | Control plane re-verifies nothing at snapshot time | accepted | It verifies at signing and stores bytes; nodes verify on every snapshot, which is the check that matters. A consistency check at build time would only catch bugs, may come later |
| R35 | Dev tooling in the control image (`ssh-keygen`, `sqlite3`, `boundgatectl`) | dev only | Documented in `Dockerfile.control`; a production image carries only `boundgate-control` |
| R36 | Node's own binding invalid → holder cleared → hub admits nobody | accepted (fail closed) | A hub whose record the control plane tampered with stops serving; the alternative (keep running on the old snapshot) would let a tampering control plane keep a node in a state it chose |
| R37 | Node-channel key rotation means re-pinning every node | documented | Same for admin keys; deliberate, see `BINDINGS.md` |
