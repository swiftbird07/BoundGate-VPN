# Development

Everything runs in containers. Go, Node and Python live in the `box` dev
container (never on the macOS host); the runtime environment is docker
compose inside the Colima VM. TUN devices, routes and nftables exist only in
the containers' network namespaces, so the host's networking is untouched.

## Toolchain

```bash
box go version          # Go 1.26.x inside the box image
box gocooldown check    # every module in go.mod is >= 14 days old
make test               # vet + unit tests
make test-race          # with the race detector (gcc lives in the box only for this)
make fuzz               # netparse fuzzing, 30 s
```

`go get` inside the box resolves to the newest version that is at least 14
days old and refuses younger explicit versions (`gocooldown`). `go get -u`
is refused. `go mod tidy` is followed by a cooldown check.

The admin UI lives in `web/` (Svelte 5, Vite, TypeScript; npm only inside
the box, `min-release-age=14`):

```bash
make web                # npm ci + vite build -> internal/control/web/dist (embedded by go:embed)
make web-check          # svelte-check
box sh -c 'cd web && npm run dev'   # dev server on :5173, /api proxied to https://localhost:18443
```

`make build-linux` (and therefore `compose-up` / `e2e`) builds the SPA
first. The `dist/` directory is git-ignored except for its placeholder.
During initial development a 7-day cooldown is acceptable for a blocked
package (`--min-release-age=7` on that one install); 14 days otherwise.

## Admin UI in the lab

Open **`http://localhost:18080`**: the `devproxy` service publishes the
admin name as plain HTTP on loopback, because browsers refuse passkeys on a
page with a certificate error and the lab certificate is self-signed
(`https://localhost:18443` still serves the same UI and is what the scripts
use with `--cacert`). Sign in with SSO: the fake IdP logs in
`martin` with groups `vpn-users, admins`, which satisfies `admin.group`.
Then register the first passkey with the token from
`deploy/compose/state/control/bootstrap.token` (Touch ID or a YubiKey; the
relying party id is `localhost`). After that the bootstrap token is dead
and `setup-dev.sh` / `e2e.sh` need an API token instead: mint one under
Admins → API tokens and save it as `deploy/compose/state/control/api.token`
(the scripts prefer that file over `bootstrap.token`). To get the bootstrap token
back, revoke every passkey or reset the state directory.

Alternatively sign in with "Use an API token" using the bootstrap token
itself (while it is alive) to look around without registering a passkey.

## Local lab

```bash
make compose-up         # builds Linux binaries in the box, builds images, starts everything
make setup-dev          # dev admin key, overlay pool, enroll + confirm + sign hub1, hub2, node-r, node-a
make e2e                # M1.5 + M1.6 + M2: up, login required, login, reachability, HA failover, session
                        # revocation, logout, node revocation, re-enrollment, confirm/sign, token reuse,
                        # grant change, DB tampering, control-plane key change
cd deploy/compose
docker compose exec node-a boundgatectl up            # endpoint: manual; hubs and node-r auto_up
./setup-dev.sh login node-a                           # user login through the fake IdP (plays the browser)
docker compose exec node-a boundgatectl logout
docker compose exec node-a boundgatectl status        # hubs, primary, routes, binding state, ignored peers
docker compose exec node-a boundgatectl identity      # fingerprint, pinned control key, pinned admin keys
docker compose exec node-a curl http://10.60.0.10     # target behind hub1/hub2
docker compose exec node-a curl http://192.168.178.10 # target in the LAN behind node-r
docker compose exec node-a boundgatectl down
./setup-dev.sh confirm node-a                         # confirm only: prints the sign command, node stays "confirmed"
./setup-dev.sh sign node-a                            # new token + signature with the dev key
./setup-dev.sh api GET /api/v1/admin/nodes            # raw admin API with the bootstrap token
./setup-dev.sh revoke node-a                          # every hub closes its tunnels within milliseconds
docker compose stop hub1                              # node-a moves to hub2 (see status)
make compose-logs
make compose-down
```

The dev admin signing key is a software ed25519 key created inside the
control container (`state/control/admin_signer`, `.pub`); `setup-dev.sh`
registers it and signs with `boundgatectl admin sign --key`. To sign with
a YubiKey instead see `BINDINGS.md`. The control image also carries
`sqlite3` so the e2e can tamper with the database.

The admin API is published on `https://127.0.0.1:18443` on the Mac
(self-signed, `--cacert deploy/compose/state/control/control.crt`); the
bootstrap token is in `deploy/compose/state/control/bootstrap.token`.

Lab topology:

| Service | Roles (granted) | public | internal | lan | overlay |
|---|---|---|---|---|---|
| control | | 172.30.0.5 | | | |
| idp | fake OpenID provider (user `martin`, groups `vpn-users, admins`) | 172.30.0.6 | | | |
| hub1 | workload: hub, subnet-router (10.60.0.0/24 snat) | 172.30.0.10 | 10.60.0.2 | | 10.21.0.1 |
| hub2 | workload: hub, subnet-router (10.60.0.0/24 snat) | 172.30.0.11 | 10.60.0.3 | | 10.21.0.2 |
| node-r | workload: endpoint, subnet-router (192.168.178.0/24 snat) | 172.30.0.30 | | 192.168.178.30 | 10.21.0.3 |
| node-a | interactive: endpoint, profile `lab` (needs a login) | 172.30.0.20 | | | 10.21.0.4 |
| target | whoami | | 10.60.0.10 | | |
| target-lan | whoami | | | 192.168.178.10 | |

Overlay addresses are assigned in approval order; the numbers above are
what `make setup-dev` produces on a fresh state.

State and logs live under `deploy/compose/state/` and `deploy/compose/logs/`
(git-ignored). Delete `state/<service>/device.*` to get a new node identity
(needs a new approval; a revoked key can never come back). Delete
`state/control` to reset the control plane; then every node's
`state/<service>/control.pin` and `admin_keys` must go too (new control
key, new admin key), so the simplest reset is `rm -rf deploy/compose/state`
and `make setup-dev`. A node that refuses the control plane with "key does
not match the pinned key" after such a reset is doing its job.

## Policies in the lab

`make setup-dev` creates the policy `lab-allow-all` (`permit(principal,
action, resource);`). Without any policy nothing is reachable. To play:

```
deploy/compose/setup-dev.sh policies
deploy/compose/setup-dev.sh policy no-lan 'forbid(principal, action, resource) when { resource.ip.isInRange(ip("192.168.178.0/24")) };'
deploy/compose/setup-dev.sh policy hub-only 'permit(principal, action, resource);' hub1     # scoped to hub1
deploy/compose/setup-dev.sh eval node-a 192.168.178.10 80
deploy/compose/setup-dev.sh policy-rm no-lan
docker compose -f deploy/compose/docker-compose.yml exec hub1 boundgatectl flows
deploy/compose/setup-dev.sh flows 'decision=deny&limit=20'
deploy/compose/setup-dev.sh tunnels active=1
```

`target-tls` (10.60.0.11) serves HTTPS with a self-signed certificate for
SNI policies: `curl -k --resolve secret.lab:443:10.60.0.11 https://secret.lab/`
from node-a. Flow records land in `logs/<node>/flow.jsonl` and in the
control plane (`setup-dev.sh flows`).

## Routed versus snat prefixes

`snat` masquerades overlay sources behind the router's LAN address and works
anywhere. `routed` keeps the real overlay source, which needs a route back
to the pool in the LAN (on a Fritz!Box: *Heimnetz → Netzwerk →
Netzwerkeinstellungen → IPv4-Routen*, network `10.21.0.0/16` via the
router node's LAN address). Prefer `routed` where you control the LAN's
routing and the ACL should see real addresses; the lab uses `snat` because
the whoami containers cannot hold routes. Overlapping home networks (several
`192.168.178.0/24`) are not supported yet.

## A node on the Mac host

`make build-darwin`, then `deploy/macos/dev.sh run` (sudo) and
`deploy/macos/e2e.sh`; details, the UDP bridge and the LaunchDaemon are in
MACOS.md. `./setup-dev.sh approve mac` and `./setup-dev.sh login mac`
treat that node like a compose service.

## Conventions

* Package docs state whether a package is in the TCB (`docs/TCB.md`).
* No new dependency without `gocooldown resolve`; pin exact versions.
* Log through the `logging` streams; no `fmt.Println` in daemons.
* Every milestone ends with tests green, docs updated, risk register
  reviewed, tag `v0.0.<m>`.
