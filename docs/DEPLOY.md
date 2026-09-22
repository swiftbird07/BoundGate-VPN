# Deploying with Docker (control plane, hubs, nodes)

Everything server-side runs as containers from **one prebuilt image**,
`ghcr.io/swiftbird07/boundgate:latest` (control plane, node, CLI and mux
in one image; amd64 and arm64). Two compose kits under `deploy/prod/`:

| Kit | Runs | For |
|---|---|---|
| `deploy/prod/all-in-one` | control plane + hub, and the mux when the two share one address (profile `mux`) | the one server everything starts with (a Hetzner Cloud VM is what this was written for) |
| `deploy/prod/node` | one node: hub, subnet router, exit node or workload endpoint | every further Linux machine: a second hub, a VM in front of a LAN (with its vTPM), a server that should only be reachable |

Clients are nodes like the Mac app (MACOS-APP.md); the dev lab in
`deploy/compose` builds its own images and is not for production. This is
a prototype deployment: read SECURITY.md before you depend on it.

## The short way

On a Linux server with Docker:

```bash
curl -fsSL https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/prod/setup.sh | sh
```

`setup.sh` asks what this server is to be (control plane with a hub, or a
node: subnet router, exit node, another hub, workload endpoint), the names,
the OIDC application, and how the server is to be updated; it writes the kit
described below into a directory (`/opt/boundgate`), with the files of the
latest release, and starts it. It keeps every file that already exists, so it
can be run again, and it touches nothing outside that directory except, if
you agree, `/etc/cron.d/boundgate-update`. To read it first: download it
(`curl -fsSLO …/setup.sh`), then `sh setup.sh`. The rest of this page is what
it does, by hand, and the layouts it does not ask about (a reverse proxy in
front, two addresses, certificates by DNS challenge). Tested by
`make setup-test`.

**Two ways to stay current**, asked by `setup.sh` and yours to change later:

| | how | what the server trusts |
|---|---|---|
| signed releases | `./update.sh` (cron): verifies the release signature here, pins the image by digest in `.env` | the release keys next to `update.sh`, nothing else ([RELEASES.md](RELEASES.md)) |
| the tag `latest` | `docker compose pull && docker compose up -d`, Dockhand, Watchtower: `BOUNDGATE_IMAGE=ghcr.io/swiftbird07/boundgate:latest` (the kits' default) | the registry and whoever can push to it (R99). CI moves `latest` only to the image of a published, signed release |

## What you need

* A server with a public IPv4 address, Docker and the compose plugin
  (Intel/AMD or arm64: the image tag covers both).
* Access to the image: `docker login gitlab.net407.com` on the server with a
  Gitea access token (scope `read:package`) unless the package is public.
* A DNS name for the control plane, `bg.example.com` below, pointing at it.
  The node channel uses `nodes.bg.example.com` only as a TLS name on the
  same port; it needs no DNS record.
* An OIDC provider. OIDC.md describes Authentik: provider + application,
  redirect URI `https://bg.example.com/api/v1/oidc/callback`, a `groups`
  scope mapping, a group `admins` for administrators.
* An SSH key to sign node approvals with, ideally a FIDO2 key:
  `ssh-keygen -t ed25519-sk -O resident -C martin@yubikey` (BINDINGS.md).
* Firewall (Hetzner Cloud Firewall and/or the host): **TCP 443 and UDP 443**
  inbound. Nothing else; port 80 is not needed.

### One address, one port

Control plane and hub share the server's only address and **port 443, TCP
and UDP**. `boundgate-mux` owns the public port and routes by TLS server
name: the admin name and `nodes.<admin name>` go to the control plane
(`127.0.0.1:8443`), `hub.boundgate` (the name every spoke uses for a hub)
goes to the hub (`127.0.0.1:8444`). It does not terminate TLS and holds no
key: both servers keep their own identity, the node channel keeps its
pinned key, the tunnel keeps its device-key mTLS. A wrong route can only
make a handshake fail.

* **TCP**: the ClientHello is read, the connection is spliced to the
  backend behind a PROXY protocol v2 header, so the control plane logs and
  rate-limits real client addresses. Let's Encrypt's validation
  (TLS-ALPN-01) passes through like any other connection for the admin name.
* **UDP/QUIC**: the server name is read from the client's Initial packet
  (its protection keys are public by design); after that, packets are
  routed by the first byte of the connection ID, which each server sets to
  its `behind_mux.id`. Between mux and server every datagram carries the
  client's address, so the servers see real peers, connections survive a
  client's address change, and the mux keeps no state for established
  connections: restarting it does not drop a tunnel.
* **TCP/443 is the tunnel's fallback**, not only the admin UI's port: a
  client whose network blocks UDP gets the same tunnel over TLS on TCP
  (ARCHITECTURE.md, "Tunnel over TCP"). The mux routes `hub.boundgate` on
  TCP to the hub's TCP listener with a PROXY header, so the hub still sees
  the client's address; the spoke returns to QUIC by itself when UDP works
  again. `boundgatectl status` shows `over TCP (UDP blocked?)` on such a
  link, the tunnel list in the UI shows `over TCP`.

### Port 443 is already taken by a web server or reverse proxy

Device-bound identity means TLS must end at BoundGate, not at a proxy: the
node channel and the tunnel are mTLS with the device certificate, which a
proxy that terminates TLS cannot present. So **nothing terminates TLS for
`nodes.<name>` and `hub.boundgate`**; a proxy passes them through at layer
4, by SNI. The admin UI is different: it is ordinary HTTPS without client
certificates, so a proxy may either pass it through as well (BoundGate's
own certificate and ACME), or terminate it and re-encrypt to the control
plane with the admin name as SNI (a WAF, the proxy's certificate; then
`acme.enabled: false`, and the proxy pins `state/control/control.crt`).

| Server name | Goes to | Protocol behind it |
|---|---|---|
| `bg.example.com` | `127.0.0.1:8443` | admin UI and API (HTTPS, WebPKI), ACME validation |
| `nodes.bg.example.com` | `127.0.0.1:8443` | node channel (mTLS), the TCP fallback of HTTP/3 |
| `hub.boundgate` | `127.0.0.1:8444` | the tunnel's TCP fallback (mTLS) |

UDP/443 stays with the mux in every setup: general-purpose proxies cannot
route QUIC by server name. If the proxy serves HTTP/3 itself on UDP/443,
switch that off (its sites keep working over TCP).

**Variant A, the mux stays in front (simplest).** The mux owns 443, the
proxy moves its HTTPS listener to another port and receives every other
server name untouched:

```yaml
# mux.yaml
default_tcp: 127.0.0.1:8080
default_tcp_proxy_protocol: true     # so the proxy sees real client addresses
```

The proxy must then expect PROXY protocol v2 on that port (nginx:
`listen 8080 ssl proxy_protocol;` + `set_real_ip_from 127.0.0.1;
real_ip_header proxy_protocol;`; Traefik entrypoint
`proxyProtocol.trustedIPs: ["127.0.0.1/32"]`; Caddy `servers { listener_wrappers
{ proxy_protocol } }`), or leave the option off and see `127.0.0.1`.
Its own ACME keeps working: HTTP-01 on port 80 is untouched, TLS-ALPN-01
arrives through the mux like any other TLS connection for its name.

**Variant B, the proxy stays on TCP/443.** The mux serves UDP only
(`no_tcp: true` in `mux.yaml`), the proxy passes the three names through
with PROXY protocol (so control plane and hub log real addresses).
BoundGate reads v2 (the mux, HAProxy, Traefik), v1 (all nginx can send)
and, from a trusted address, connections without a header (an HTTP proxy
that re-encrypts to the admin name cannot send one; BoundGate then sees the
proxy's address). `behind_mux.no_proxy_protocol: true` switches header
parsing off altogether. Traefik, as a dynamic configuration file:

```yaml
tcp:
  routers:
    bg-control: { rule: "HostSNI(`bg.example.com`) || HostSNI(`nodes.bg.example.com`)", entryPoints: [websecure], service: bg-control, tls: { passthrough: true } }
    bg-hub:     { rule: "HostSNI(`hub.boundgate`)", entryPoints: [websecure], service: bg-hub, tls: { passthrough: true } }
  services:
    bg-control: { loadBalancer: { proxyProtocol: { version: 2 }, servers: [{ address: "127.0.0.1:8443" }] } }
    bg-hub:     { loadBalancer: { proxyProtocol: { version: 2 }, servers: [{ address: "127.0.0.1:8444" }] } }
```

Traefik's `websecure` entrypoint keeps terminating TLS for every other
router; passthrough routers are matched by SNI first. Traefik in Docker
needs `network_mode: host` or access to the mux/control/hub ports, and
the control plane and hub then listen on an address Traefik can reach
(`listen` in their yaml, `behind_mux.trusted` covering Traefik's
address). nginx (`stream` context, not `http`):

```nginx
stream {
  map $ssl_preread_server_name $bg_upstream {
    bg.example.com        127.0.0.1:8443;
    nodes.bg.example.com  127.0.0.1:8443;
    hub.boundgate         127.0.0.1:8444;
    default               127.0.0.1:8081;   # your http{} server, moved off 443
  }
  server {
    listen 443;
    ssl_preread on;
    proxy_pass $bg_upstream;
    proxy_protocol on;                       # v1; the http{} server then needs "listen 8081 ssl proxy_protocol;"
  }
}
```

The [nginx-waf](https://gitlab.net407.com/BDH/Nginx-WAF) project renders
exactly this from a `[[boundgate]]` entry in its `hosts.toml`, with its geo
gate applied to the BoundGate names and the admin UI as one of its hosts.
`FRONT=nginx deploy/prod/rehearsal.sh` runs the rehearsal behind a stock
nginx (mux on UDP only), `NGINX_STREAM_FILE=` with a stream block of your
own.

HAProxy: `mode tcp`, `tcp-request inspect-delay 5s`, `tcp-request content
accept if { req.ssl_hello_type 1 }`, `use_backend bg_hub if { req.ssl_sni -i
hub.boundgate }`, `use_backend bg_control if { req.ssl_sni -i bg.example.com
nodes.bg.example.com }`, backends with `server … 127.0.0.1:8444 send-proxy-v2`.
Caddy: the `layer4` app with `tls sni` matchers and `proxy` handlers
(`proxy_protocol v2`).

**Variant C, the proxy is another machine.** A WAF or load balancer in
front of the network owns the public TCP/443 and reaches the BoundGate host
on one private port; UDP is forwarded to the BoundGate host directly (NAT).
The mux then serves both, on different sockets, and the proxy needs a single
target for every BoundGate name:

```yaml
listen: ":8443"                 # UDP, from the NAT
listen_tcp: "10.0.0.5:8080"     # TCP, from the proxy only
trusted_fronts: [10.0.0.2]      # the proxy: its PROXY header (v1 or v2) names the client
```

The mux hands that client address on to control plane and hub (PROXY v2),
which keep `behind_mux.trusted: [127.0.0.1]`. A connection from a trusted
front without a header (the HTTP hop to the admin name) is relayed with the
proxy's address. `public_addr` of the hub and `control.addr` of the nodes
name the public address and port, not these.

Whichever variant: the firewall still opens only TCP 443 and UDP 443; the
proxy's HTTP-01 port 80 if it needs it.

If UDP/443 cannot be had at all on the server, everything still works over
TCP alone: the node channel and the tunnel both fall back, at the cost of
TCP-in-TCP for the tunnel. Do not run that way on purpose.

## Install

```bash
scp -r deploy/prod/all-in-one root@SERVER:/opt/boundgate        # the compose file and the three examples
ssh root@SERVER
cd /opt/boundgate
for f in mux control hub; do cp $f.yaml.example $f.yaml; done            # replace bg.example.com everywhere, fill in oidc
echo COMPOSE_PROFILES=mux > .env                                        # one address: the mux owns 443. Two addresses: skip, see the compose file
mkdir -p state/control && umask 077 && printf '%s\n' 'THE-OIDC-CLIENT-SECRET' > state/control/oidc.secret
sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000          # QUIC wants larger UDP buffers; persist in /etc/sysctl.d
docker compose pull
docker compose up -d mux control
docker compose logs -f control
```

Compose does not build anything: it pulls `:latest`, which the CI job
(`.gitea/workflows/image.yml`) pushes for every commit on `main`, tagged
also `sha-<commit>`, and every `v*` tag as `:<tag>`. Pin one of those in
`.env` (`BOUNDGATE_IMAGE=ghcr.io/swiftbird07/boundgate:v0.1.2`) when
"whatever is on main" is not what you want on a server. Updating is
`docker compose pull && docker compose up -d`. Without a CI runner,
`make image-push` on the Mac does the same build (both architectures,
buildx from the `docker:cli` image because Colima ships none; `docker
login gitlab.net407.com` first with a token that has `write:package`).
`make image` builds `boundgate:local` for this machine only.

On its first start the control plane creates its database, the long-lived
node-channel key (`state/control/nodes.key`: **back it up**, every node pins
it) and the bootstrap token, and logs the fingerprint of the node-channel
key ("node-channel key … fingerprint"). Note that fingerprint: it is what
the Mac app shows before it enrolls. The admin certificate comes from
Let's Encrypt at the first browser request (TLS-ALPN-01 on port 443 itself);
the first page load takes a few seconds. To rehearse without rate limits,
set `acme.directory_url` to the staging directory first.

### Certificates: three ways

| | When | How |
|---|---|---|
| **Built-in, TLS-ALPN-01** (default) | port 443 is reachable from the internet | `acme.enabled: true`; nothing else. Validation is a TLS handshake on 443 with ALPN `acme-tls/1`, which passes through the mux or an SNI-passthrough proxy |
| **DNS-01 through the `acme-dns` service** | the CA cannot reach 443: geo-blocking, `admin_allow`, a firewall that admits only your addresses | `acme.enabled: false`, `tls_cert`/`tls_key` pointing at `/var/lib/boundgate/certs/certificates/<name>.crt|.key`; in `.env`: `BG_DOMAIN`, `LEGO_EMAIL`, `LEGO_DNS=<provider>` and the provider's own variables (`HETZNER_API_KEY`, `CLOUDFLARE_DNS_API_TOKEN`, `INWX_USERNAME`/`INWX_PASSWORD`, …, see [lego's provider list](https://go-acme.github.io/lego/dns/)); start with `--profile dns-acme` (or `COMPOSE_PROFILES=mux,dns-acme`). lego issues, renews 30 days before expiry, and the control plane reloads the files within 30 s of a change (log line "admin certificate reloaded") |
| **Your own files** | an existing wildcard, an internal CA, certbot/acme.sh on the host | `acme.enabled: false`, `tls_cert`/`tls_key`; renewals are picked up the same way |

Let's Encrypt validates TLS-ALPN-01 from several vantage points in
different countries, so a geo-IP block on 443 rules the built-in way out;
DNS-01 needs no inbound access at all. The node channel is not involved in
any of this: nodes pin the control plane's own key (`nodes.key`), not a
CA-issued certificate.

### Who may open the admin UI

By default anyone who can reach 443 gets the login page (the node channel
must be public; the admin UI merely shares the listener, see
SECURITY.md R29/R81). `admin_allow` in `control.yaml` restricts the admin
name to client prefixes:

```yaml
admin_allow: [100.96.0.0/16, 10.0.0.0/8, 203.0.113.7]   # the overlay, a private network, the office
```

Outside the list every request for the admin name gets 403, with one
exception: `GET /api/v1/oidc/callback`. The identity provider sends users'
browsers back there when they sign in to their devices, from wherever they
are (a phone on a mobile network). An *admin* login that arrives there from
outside the list is refused as well. The node name is never restricted.
Until 2026-09-22 the check was made at the TLS handshake, which also cut off
every user's sign-in from outside the list. Client addresses are what
the mux or proxy reports (PROXY protocol), so behind
`no_proxy_protocol: true` every client is the proxy. Administering
BoundGate through its own overlay (the control plane's host as a hub,
`admin_allow` = the overlay pool) is the tightest arrangement: then the
first admin logs in over an SSH tunnel (`ssh -L 8443:127.0.0.1:8443` and
`admin_allow` including `127.0.0.1`), enrolls the hub and their own
machine, and the UI is reachable only from approved devices from then on.

## First administrator

1. Open `https://bg.example.com/`, sign in through your IdP (your account
   must be in the `admins` group). The session is `oidc_only`: it can do
   nothing yet.
2. Register a passkey. The very first one needs the bootstrap token:
   `cat state/control/bootstrap.token`. After that the token is dead
   (ADMIN-AUTH.md); further administrators are approved by an existing one.
3. *Admins › Admin signing keys*: add the public key of your signing key
   (`~/.ssh/id_ed25519_sk.pub`). The list of signing keys is itself signed:
   the page shows a `boundgatectl admin sign-signers …` command, run it
   where the key is, compare the fingerprints it prints, type `yes`, touch
   the key. The first list is signed by its own key; every later change
   (a second YubiKey, a colleague, removing a lost key) by a key that is
   already in the list. Nodes pin the list at enrollment and follow such
   changes by themselves, nothing is re-enrolled (BINDINGS.md). Add a second
   key soon: losing **all** keys of the list is the one thing that cannot
   be repaired (R23).
4. *Settings › Overlay network*: choose the overlay pool **before** the first
   approval. It must not collide with anything your clients already use;
   the default `10.21.0.0/16` does if another VPN of yours lives in 10.x.
   `100.96.0.0/16` (from the CGNAT range) is rarely taken.

## The hub

```bash
docker compose up -d hub
docker compose exec hub boundgatectl enroll      # shows the hub's fingerprint; compare the control pin with the fingerprint from the log
```

In the UI: *Nodes › pending › Confirm…*, kind `workload` (preset when the node asks for the hub role), role `hub`,
public address `bg.example.com:443` (as in `hub.yaml`), then run the sign command it shows on
the machine with your signing key (`boundgatectl admin sign …`, touch the
key). `auto_up: true` brings the hub up by itself once it is approved:
`docker compose exec hub boundgatectl status`.

Without a policy nothing is allowed. For a first test, *Policies › New*
with the builder: *permit*, *any principal in group `vpn-users`*, *any
resource*; then tighten. The **sanity check** on the same page tells you
what a given node may reach before you save.

The hub is reachable over the overlay at its own overlay address (shown in
*Nodes*): `ssh root@100.96.0.1` from an approved, connected and permitted
client reaches the server's sshd without it being open to the internet.
To route further (a Hetzner private network, or the internet as an exit
node) grant `subnet-router`/`exit-node` with prefixes. On a Docker host
two things stand in the way, and the node takes care of both: forwarding
(`net.ipv4.ip_forward=1`, which Docker sets itself), and Docker's `FORWARD`
policy, which is *drop*. While it is up, a node that forwards puts
`iifname "bg0" accept` and `oifname "bg0" accept` into the chain Docker
leaves to the administrator, `DOCKER-USER`, and says so in its log; it takes
them out again at `down` and leaves every other rule alone. (Since v0.1.4.
Before, or with iptables-legacy, which nft cannot see, by hand:
`iptables -I DOCKER-USER -i bg0 -j ACCEPT; iptables -I DOCKER-USER -o bg0 -j ACCEPT`.)
What leaves the tunnel device has passed the node's ACL.

**Containers on that same host are a case of their own.** Docker 28 and
later drop every packet addressed to a container's own address that arrives
on another interface, in the `raw` chain before `DOCKER-USER`, so an
overlay peer cannot reach `172.x.y.z` there even though the node's rules
allow the forwarding. Reach such a service through a published port on the
host's address instead, or create its network with
`com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected` (or
`routed`), which is what the rehearsal's step 8 does. Traffic that only
passes the host, to a LAN or the internet, is not affected.

**An exit node for iPhones needs `dns` on the hub.** Set it in `hub.yaml`,
for example `dns: [10.20.0.1]`, a resolver reachable behind the hub. With
the exit node's default route in the tunnel, iOS asks only the resolvers
the tunnel brings along and ignores those of the Wi-Fi or the mobile
network. Without `dns` the tunnel brings none: the iPhone resolves no name
and reports "not connected to the internet", while its connections by
address still work. The tunnel's log then says "the exit node's hub offers
no DNS resolvers" (docs/IOS.md). Android, Linux, macOS and Windows do not
need it.

## Further nodes

Every other Linux machine gets `deploy/prod/node`: copy the directory, fill
in `node.yaml` (the example has a block per role: subnet router with its
LAN prefix, exit node, a second hub, a workload endpoint), then

```bash
docker compose pull && docker compose up -d
docker compose exec node boundgatectl enroll        # confirm + sign in the UI; auto_up brings it up
docker compose exec node boundgatectl status
```

Host network, `NET_ADMIN` and `/dev/net/tun` are what a node needs; a
router additionally `net.ipv4.ip_forward=1` on the host (Docker sets it
itself); the `DOCKER-USER` rules above it writes itself. A VM with a
vTPM (Proxmox: add a TPM 2.0 device) passes `/dev/tpmrm0` into the
container and sets `key_kind: tpm2` (TPM.md); the admin then grants
`hardware_bound` at approval. `./state` holds the device identity: keep it
across updates, and note that copying it to a second machine is exactly
the cloning a TPM key prevents.

## The Mac

Build and install the app (MACOS-APP.md), *Install service*, enter
`bg.example.com`, compare the control-plane fingerprint with the one from
the log, *Request access*, confirm and sign the Mac in the UI (kind
`interactive`, role `endpoint`), *Connect*, sign in.

If another VPN on the Mac takes the default route (WireGuard with
`AllowedIPs = 0.0.0.0/0`), the node refuses to pin the hub's address into
that tunnel (R64): disconnect it, or exclude the server's address from it.
A VPN that owns the overlay range stops `Connect` with an explanation (R66).

## Rehearsal

`make rehearsal` builds `boundgate:local` and runs the shipped all-in-one
compose file with it in the local Docker VM (`deploy/prod/rehearsal.sh`):
mux, control plane and hub on one address and port 443, a client in its own
container that enrolls over HTTP/3, is approved and signed, brings a tunnel
up on the shared UDP port and pings the hub; it checks that the hub sees
the client's real address and that a mux restart does not interrupt the
tunnel. Then it blocks UDP/443 in the client's namespace: the tunnel comes
back over TCP through the mux, the hub still sees the client's address,
and once UDP is allowed again the client moves back to QUIC.

Step 8 is the one with the traffic in it: the hub is an exit node
(`0.0.0.0/0`, snat), and the client downloads 20 MB from a target in
another Docker network, once over QUIC and once over the TCP fallback,
and compares the SHA-256 both times. That is the path a phone takes
through a hub on a Docker host, and it covers what broke in production:
a packet size the path cannot carry (nothing arrives, or large transfers
stall), and Docker's `FORWARD` policy, which the node opens in
`DOCKER-USER`.

## Operating it

| | |
|---|---|
| Back up | `state/control/` (database, `nodes.key`/`nodes.crt`, ACME account and certificates), `state/hub/` (the hub's identity) |
| Update | `./update.sh` in the kit directory, by hand or from cron (`17 3 * * * cd /opt/boundgate && ./update.sh -q`): installs the latest **signed release** by image digest and goes back if it does not stay up ([RELEASES.md](RELEASES.md)). Copy `deploy/prod/update.sh` and `release_keys` next to the compose file. The database migrates itself; nodes reconnect |
| Logs | `logs/*/*.jsonl`, `docker compose logs`; audit and flows also in the UI |
| Lost `nodes.key` | every node refuses the control plane until its pin is reset (`boundgatectl reset` on app nodes, delete `control.pin` elsewhere) and enrolls again |
| New or lost signing key | add or remove it under *Admins*, sign the change with a key of the current list; nodes follow, nothing is re-enrolled. Nodes approved with a removed key need a new signature |
| Lost **all** signing keys | every node has to be re-enrolled (R23) |

## Risks

SECURITY.md, in particular R21 (the hub sees overlay traffic until M7),
R24/R73 (trust on first use at enrollment), R67 (no TPM attestation),
R76 (ACME, shared host), R77/R78 (the mux), R79 (the image), R80 (the
TCP fallback) and R81 (admin_allow).
