# Deploying on a server (control plane + hub)

One Linux server (a Hetzner Cloud VM is what this was written for) runs the
control plane and a hub with Docker Compose; clients are nodes like the Mac
app (MACOS-APP.md). This is a prototype deployment: read SECURITY.md before
you depend on it.

## What you need

* A server with a public IPv4 address, Docker and the compose plugin.
  `make server-bundle GOARCH=amd64` for Intel/AMD machines (Hetzner CX/CPX),
  `GOARCH=arm64` for Ampere (CAX).
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
* A hub's TCP fallback for tunnels does not exist yet (plan: M8.2); the mux
  already routes `hub.boundgate` on TCP once a hub listens there.

### Port 443 is already taken by a web server or reverse proxy

Device-bound identity means TLS must end at BoundGate, not at a proxy: a
proxy that terminates TLS cannot present the node's client certificate.
What works is **passing the connection through by server name** (layer 4):

| Setup | TCP/443 | UDP/443 |
|---|---|---|
| mux in front (simplest) | mux; `default_tcp: 127.0.0.1:8080` hands every other name to your web server, TLS untouched. Move the web server's HTTPS listener to that port | mux |
| your proxy stays in front | your proxy passes `bg.example.com` and `nodes.bg.example.com` through by SNI to `127.0.0.1:8443` with PROXY protocol v2 (Traefik: TCP router `HostSNI(...)` + `tls.passthrough`, `proxyProtocol.version: 2`; nginx: `stream` + `ssl_preread`, `proxy_protocol on`; HAProxy: `mode tcp`, `req.ssl_sni`, `send-proxy-v2`; Caddy: layer4 app). Without PROXY protocol: `behind_mux.no_proxy_protocol: true`, and the control plane sees the proxy's address | mux with `no_tcp: true`. General-purpose proxies cannot route QUIC by name; if yours serves HTTP/3 itself on UDP/443, that has to move or be switched off (its sites keep working over TCP) |

If UDP/443 cannot be had at all, nodes still reach the control plane (its
node channel falls back to TCP), but there is no tunnel until M8.2.

## Install

```bash
make server-bundle GOARCH=amd64                     # on the Mac: dist/boundgate-server-linux-amd64.tar.gz
scp dist/boundgate-server-linux-amd64.tar.gz root@SERVER:/opt/
ssh root@SERVER
cd /opt && tar xzf boundgate-server-linux-amd64.tar.gz && cd boundgate-server
for f in mux control hub; do cp $f.yaml.example $f.yaml; done            # replace bg.example.com everywhere, fill in oidc
mkdir -p state/control && umask 077 && printf '%s\n' 'THE-OIDC-CLIENT-SECRET' > state/control/oidc.secret
sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000          # QUIC wants larger UDP buffers; persist in /etc/sysctl.d
docker compose up -d --build mux control
docker compose logs -f control
```

On its first start the control plane creates its database, the long-lived
node-channel key (`state/control/nodes.key`: **back it up**, every node pins
it) and the bootstrap token, and logs the fingerprint of the node-channel
key ("node-channel key … fingerprint"). Note that fingerprint: it is what
the Mac app shows before it enrolls. The admin certificate comes from
Let's Encrypt at the first browser request (TLS-ALPN-01 on port 443 itself);
the first page load takes a few seconds. To rehearse without rate limits,
set `acme.directory_url` to the staging directory first.

## First administrator

1. Open `https://bg.example.com/`, sign in through your IdP (your account
   must be in the `admins` group). The session is `oidc_only`: it can do
   nothing yet.
2. Register a passkey. The very first one needs the bootstrap token:
   `cat state/control/bootstrap.token`. After that the token is dead
   (ADMIN-AUTH.md); further administrators are approved by an existing one.
3. *Admins › Admin signing keys*: add the public key of your signing key
   (`~/.ssh/id_ed25519_sk.pub`). Nodes pin these keys at enrollment, so add
   every key you want to be able to sign with **before** the first node
   enrolls (R23).
4. *Settings › Overlay network*: choose the overlay pool **before** the first
   approval. It must not collide with anything your clients already use;
   the default `10.21.0.0/16` does if another VPN of yours lives in 10.x.
   `100.96.0.0/16` (from the CGNAT range) is rarely taken.

## The hub

```bash
docker compose up -d --build hub
docker compose exec hub boundgatectl enroll      # shows the hub's fingerprint; compare the control pin with the fingerprint from the log
```

In the UI: *Nodes › pending › Confirm…*, kind `workload`, role `hub`,
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
node) grant `subnet-router`/`exit-node` with prefixes, and mind two things
on a Docker host: `sysctl -w net.ipv4.ip_forward=1`, and Docker's
`FORWARD` policy is *drop*, so allow the tunnel device:
`iptables -I DOCKER-USER -i bg0 -j ACCEPT; iptables -I DOCKER-USER -o bg0 -j ACCEPT`.

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

`deploy/server/rehearsal.sh` runs exactly this kit in the local Docker VM:
mux, control plane and hub on one address and port 443, a client in its own
container that enrolls over HTTP/3, is approved and signed, brings a tunnel
up on the shared UDP port and pings the hub; it checks that the hub sees
the client's real address and that a mux restart does not interrupt the
tunnel. `make rehearsal` builds the bundle for the VM's architecture first.

## Operating it

| | |
|---|---|
| Back up | `state/control/` (database, `nodes.key`/`nodes.crt`, ACME account and certificates), `state/hub/` (the hub's identity) |
| Update | new bundle, `docker compose up -d --build`; the database migrates itself; nodes reconnect |
| Logs | `logs/*/*.jsonl`, `docker compose logs`; audit and flows also in the UI |
| Lost `nodes.key` | every node refuses the control plane until its pin is reset (`boundgatectl reset` on app nodes, delete `control.pin` elsewhere) and enrolls again |
| Lost all signing keys | every node has to be re-enrolled (R23) |

## Risks

SECURITY.md, in particular R21 (the hub sees overlay traffic until M7),
R24/R73 (trust on first use at enrollment), R67 (no TPM attestation),
R76 (ACME, shared host) and R77/R78 (the mux).
