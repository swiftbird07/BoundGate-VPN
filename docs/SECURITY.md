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
| Stolen OIDC tokens | Tokens exist only for the duration of the code exchange inside the control plane; nothing token-like reaches a node. A session is a control-plane row bound to a node id and only ever travels inside snapshots; a hub honours it only on that node's mTLS connection |
| Session replay from another device | Impossible by construction: the session names a node id, the tunnel proves the node's key |
| Login started by one node, completed for another | `state` binds the callback to the flow's node; the flow id is readable only by that node; the code is single use with PKCE and nonce |
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
| Compromise of the control plane | Can delete nodes (deny service), change unsigned fields (name, hub public address), policy (M3) and **user sessions** (it can attach any user to any interactive node; the ACL then trusts that user), and route traffic through a chosen *approved* hub. It cannot make an interactive node a workload (kind is signed). Cannot forge a device key, invent a node, change roles or prefixes, or move an overlay address: those are in the admin-signed binding that every node verifies against keys pinned at enrollment (`BINDINGS.md`). Cannot impersonate the control plane to enrolled nodes either (pinned key). |
| TPM firmware vulnerabilities | Out of scope; re-enroll all nodes if one becomes known. |

## Risk register

| # | Risk | Status | Mitigation / decision |
|---|---|---|---|
| R1 | connect-ip-go is pre-1.0 (v0.2.0 pinned, v0.3.0 blocked by cooldown until 2026-09-22) | open | All use isolated in `internal/transport`; `Tunnel` wrapper; pin exact versions |
| R2 | http3 exposes the QUIC connection only via `ConnContext` | verified M0 | `ConnContext` runs after the handshake; `PeerFromTLSState` re-verifies per request |
| R3 | Enroll endpoint is reachable without approval | mitigated M1 | Creates `pending` rows only; rate limit per source IP; expiry 24 h; fingerprint shown prominently |
| R4 | Admin approves without comparing the fingerprint | partly M1 | API takes the confirmed fingerprint and refuses mismatches; UI (M4) will require it; procedure in ENROLLMENT.md |
| R5 | Cedar schema validation not used; attribute typos only show up at evaluation time | accepted M3 | Policies are parsed on save; `POST /admin/acl/evaluate` dry-runs on live state and returns evaluation errors; the flow log records them per flow |
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
| R38 | OIDC callback is unauthenticated and on the public admin name | mitigated M2 | State (24 random bytes) binds it to a flow; flows expire in 10 min; code single use; PKCE + nonce; errors are generic; audited in `user-auth` |
| R39 | Session lifetime is a fixed 10 h, no revocation on IdP side changes | accepted | The control plane never talks to the IdP after login; admins revoke sessions in BoundGate. Authentik logout/disable does not end a BoundGate session before its lifetime. Back-channel logout later |
| R40 | Subnet routers cannot enforce sessions per peer | accepted | They see packets from the hub tunnel; the hub enforces before forwarding, the ACL (M3) decides per flow with the user |
| R41 | Session expiry between snapshots | mitigated M2 | Hubs check `expires_at` every 10 s and at Accept; the control plane sweeps every 15 s and bumps; a stale snapshot admits nobody |
| R42 | The fake IdP and its default secret in the lab | dev only | `boundgate-fakeidp` logs anyone in; only reachable on the compose network; production config uses Authentik with a secret file |
| R43 | A router identifies the principal by source address, not by a handshake | accepted M3 | The hub verified that the source belongs to the peer (`allowedSource`) before forwarding, and the hub role is admin-signed; a compromised hub could already read and inject traffic (R21). The endpoint-side handshake comes with M7 |
| R44 | SNI is only known after the TCP handshake; the first packets of a forbidden TLS connection have already been forwarded | accepted M3 | Only the SYN/ACK exchange passes; the ClientHello that reveals the name is dropped and both ends get RSTs; no application data reaches the server. ECH hides the name entirely (then only IP/port policies apply) |
| R45 | Verdict cache: a flow allowed under an old policy or session keeps running | mitigated M3 | Every snapshot re-evaluates all open decided flows and closes the ones no longer permitted; a peer's removal closes its flows; hubs close the tunnel on session end |
| R46 | Flow-table exhaustion by a peer opening many 5-tuples | mitigated M3 | Bounded table (65536), new flows dropped above it (fail closed) and counted; per-peer quotas are future work |
| R47 | Shipped logs are self-reported by nodes | accepted M3 | The reporter is authenticated by mTLS and its id is stamped by the control plane; tunnel events are accepted from hubs only; batches are bounded (2000 events, 4 MB). A compromised node can lie about its own flows, not about others' |
| R48 | Asymmetric hub paths see the responder as principal | open | Documented in ACL.md; permit both directions or keep both ends on one primary hub; M7 direct paths remove the hub from the middle |
| R49 | A policy that does not compile on a node | mitigated M3 | The control plane refuses to store it; a node that still receives one (version skew) skips it, logs it and shows it in `boundgatectl status`; it never widens access |
| R50 | Denied flows are logged once per 10 s per 5-tuple | accepted M3 | Prevents log floods from port scans; the counter of denied flows is in the node status |
| R51 | Admin session cookie theft (XSS, malware on the admin's machine) | mitigated M4 | `HttpOnly`, `Secure`, `SameSite=Lax`, 1 h lifetime (8 h lab), CSP `default-src 'self'` on the SPA, no inline scripts; every privileged action is audited with the session's subject; logout revokes server-side. A stolen cookie is still a full admin for its lifetime: shorten `admin.session_lifetime` where that matters |
| R52 | CSRF against cookie-authenticated mutations | mitigated M4 | `SameSite=Lax` plus the mandatory `X-Requested-With: BoundGate` header on non-GET (tested); bearer tokens carry no ambient authority |
| R53 | OIDC alone would be enough for an attacker who phishes the IdP login | mitigated M4 | The session stays `oidc_only` (can only run passkey ceremonies) until a WebAuthn assertion with user verification succeeds; phishing-resistant by origin binding (`rp_id`) |
| R54 | The first passkey (bootstrap) is the root of admin trust | accepted M4 | It requires the bootstrap token from the control plane's state directory (file system access) *and* an OIDC login in the admin group; the token is dead afterwards. Rotate by revoking every passkey (then the token lives again) or resetting state |
| R55 | A pending passkey approved by the wrong admin | mitigated M4 | Only `full` admins approve, never for themselves; the approval is audited with both subjects. The approver should verify out of band that the requester registered it |
| R56 | API tokens are bearer secrets without a second factor | accepted M4 | Only their hash is stored; creation and revocation are audited; expiries are configurable and the UI defaults to 30 days; treat them like SSH deploy keys |
| R57 | Open redirect through `next=` after login | mitigated M4 | `next` must start with `/` and not `//`; the callback checks the flow cookie so a captured callback URL cannot finish a login in another browser (tested) |
| R58 | The policy builder generates Cedar the admin did not intend | mitigated M4 | The generated Cedar and an English summary are shown live; the sanity check evaluates a sample connection with the real engine against the unsaved draft; storing still validates; the raw text remains editable |
| R61 | macOS node keeps its device key as a file (`softkey`) | accepted M5 | Root-only state directory; the binding carries `hardware_bound: false`, so policies can exclude such nodes (`principal.hardware_bound`). Secure Enclave keys are future work |
| R62 | Stale bypass host routes after a crash pin a hub or the control plane to an old gateway | mitigated M5 | Network journal (`netstate.json`): the next start removes what the dead process left; launchd `KeepAlive` makes that next start prompt. Tested with a fake configurator and by `deploy/macos/e2e.sh` (kill -9) |
| R63 | `hub_addrs` lets local configuration redirect where a hub is dialed | accepted M5 | The hub is authenticated by the pinned key from its admin-signed binding; a wrong address can only fail. The node configuration is root-owned, and root can already change every route |
| R64 | A second VPN on the Mac captures the hub or control-plane path | mitigated M5 | A bypass target that currently routes through another `utun` is refused with an explicit error instead of being pinned into that tunnel; overlapping prefixes are a profile matter (R25) |
| R65 | Lab UDP-over-TCP bridge in front of the hubs | accepted dev | Lab only, loopback only, sees QUIC ciphertext; exists because Colima's default forwarder drops UDP. Not part of any production path |
| R66 | The overlay pool or an announced prefix overlaps a network the machine already uses (home LAN, a second VPN); the more specific route would silently take that traffic | mitigated M5 | Overlap guard in the node: pool conflict refuses `up` before any change, a conflicting prefix is skipped and shown (`not routed`), `allow_overlap` is an explicit opt-out; `/0` and `/1` exempt. Unit-tested (`TestConflictWith`). `deploy/macos/netbackup.sh` snapshots, diffs and repairs the Mac's routing state. Not a security boundary; real collisions need 1:1 NAT (R25) |
| R67 | `hardware_bound` rests on the node's own report: no TPM attestation (EK certificate, credential activation) | accepted M6 | The report grants nothing: an admin grants `hardware_bound` at confirm and signs it into the binding, so neither the node alone nor the control plane can set it. Granting without a report is refused. Remote attestation is future work; vTPMs and swtpm have no manufacturer chain anyway (TPM.md) |
| R68 | vTPM: the hypervisor admin can copy the vTPM state with the VM (clone, backup) | documented M6 | Protects against guest-level theft only; TPM.md says so per TPM type, the admin can decline `hardware_bound` for such nodes, clones must enroll with a fresh state directory |
| R69 | TPM key without password or policy session; TPM bus unencrypted | accepted M6 | Root on the machine can use (not extract) the key while it has the machine, as with any unattended machine key; the user factor is OIDC. Parameter encryption against bus interposers is future work; irrelevant for fTPM/vTPM |
| R70 | Raw socket TPM: the daemon flushes all transient objects at start | accepted dev | Only for `unix:`/`tcp:` devices (swtpm), which belong to one node; never done on `/dev/tpmrm0` |
| R71 | TPM cleared or mainboard replaced: the node identity is gone | documented M6 | By design (no export, no backup of the key); the node enrolls again, the old node is revoked |
| R72 | The daemon socket is open to the Mac's `admin` group (app without sudo) | accepted M8 | Administrators can become root anyway; standard users and other groups get `EACCES`. What the socket offers is limited to this node's own VPN: no file access, no command execution. Servers keep `root` only (no `socket_group`) |
| R73 | The control plane address comes from the user, and its key is pinned on first use | documented M8 | Same TOFU as `boundgatectl enroll` (R24): the app shows the pinned fingerprint before the enrollment request and says to compare it. `configure` is refused once an address is set; `reset` (only while down) removes address, pin and admin keys together, never one without the others. A configuration file that names the control plane cannot be overridden from the socket |
| R74 | Root daemon inside an app bundle that administrators can modify | accepted M8 | Same trust level as R72 (an admin is root-equivalent). The bundle is signed with the hardened runtime; a Developer ID build is notarized. Stage 2 (system extension) moves the code out of the user-writable bundle |
| R75 | The app opens the login URL it gets from the daemon in the browser | mitigated M8 | Only `https`/`http` URLs are opened; the URL comes from the pinned control plane over the node channel. The app never sees credentials: sign-in happens at the IdP in the browser |
| R76 | Built-in ACME client for the admin name (autocert, TLS-ALPN-01); control plane and hub share a host | accepted M8 | ACME only touches the browser-facing certificate; the node channel keeps its own pinned key and is never served the ACME certificate (tested: `TestSNISplitWithACMECallback`). Host whitelist = `server_name` + `extra_names`. A host that runs both the control plane and a hub concentrates R21 and the control-plane risks in one machine: acceptable for a small deployment, separate them otherwise; never share one UDP port between them (DEPLOY.md) |
| R60 | Lab devproxy: the admin name as plain HTTP on 127.0.0.1:18080, cookies without `Secure` for that origin | accepted dev | Compose only, bound to loopback; exists because browsers refuse passkeys behind a self-signed certificate. The relaxation is driven by an explicit `http://` entry in `admin.origins`; production lists only `https://` origins and has no proxy |
| R59 | WebAuthn implementation (go-webauthn v0.18.0) and the CBOR/COSE parsers are in the admin TCB | accepted M4 | Pinned; attestation is not requested (`none`), so the metadata/attestation code paths stay unused; a software-authenticator test pins the expected ceremony |
| R11 (update) | Authentik `groups` claim | documented M2 | Scope mapping in `OIDC.md`; missing groups mean an empty group list, never a failure |
