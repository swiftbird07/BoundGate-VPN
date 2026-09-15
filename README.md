# BoundGate

Device-bound zero-trust remote access. A device gets in only with a key that
cannot leave it (TPM 2.0, later Secure Enclave), a user only with OIDC, and
every flow only if a Cedar policy says so. The tunnel is standard HTTP/3:
CONNECT-IP (RFC 9484) over QUIC on UDP/443.

Status: prototype, milestone M1.6 (node model: control plane on port 443,
one `boundgate-node` binary with the roles endpoint / subnet-router / hub /
exit-node, hub-and-spoke overlay with HA; enrollment with manual admin
confirmation and an admin-signed binding (SSHSIG, YubiKey) that every node
verifies, so the control plane cannot invent or upgrade nodes; pinned
control-plane key; local compose lab). See `docs/ARCHITECTURE.md`,
`docs/TCB.md`, `docs/SECURITY.md`, `docs/BINDINGS.md` and `docs/DEV.md`.

```bash
make test
make compose-up && make setup-dev   # dev admin key, overlay pool, enroll + confirm + sign hub1, hub2, node-r, node-a
cd deploy/compose && docker compose exec node-a boundgatectl up
make e2e                            # up -> targets -> hub failover -> revoke -> re-enroll -> sign flow -> tampering -> key pin
```
