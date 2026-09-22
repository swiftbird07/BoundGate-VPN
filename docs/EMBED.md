# The embedded engine (M8.5)

On a server or a Mac with the LaunchDaemon, the node is a root daemon: it
opens its own TUN, sets routes with `route`/`ip`, reads its key from a file,
the TPM or the Secure Enclave helper, and talks to its UI over a unix socket.
An iOS packet tunnel, a macOS network extension and Android's `VpnService`
cannot do any of that. They are handed a finished tunnel device, want the
whole network configuration in one declarative call, and the device key lives
in a key store only the app can use.

`internal/embed` runs the same node under those conditions. Nothing in the
data path, the ACL, the bindings or the control channel is different.

```
            app process (iOS app, Android app)          packet tunnel / VpnService
            ┌──────────────────────────────┐            ┌──────────────────────────────┐
  UI ──────▶│ Request("GET","/v1/status")  │            │ Request(…)  ◀── app messages │
            │        │                     │            │        │                     │
            │   embed.Engine ── node ──────┼── lock ────┼── embed.Engine ── node       │
            │        │                     │  state dir │        │                     │
            │   Platform: key signs,       │            │   Platform: Apply(settings)  │
            │   Apply refuses (no tunnel)  │            │   → fd, key signs, Log       │
            └──────────────────────────────┘            └──────────────────────────────┘
```

## Platform contract

The app implements `embed.Platform`:

| Method | What the app does |
|---|---|
| `Apply(settings) (fd, error)` | Installs the whole configuration: overlay `address` (a /32), `mtu`, `routes` (sorted; `0.0.0.0/0` comes as its two halves) and `excluded` hosts (control plane, hubs, IdP), and `dns`: the resolvers the primary hub offers (hub option `dns`; empty keeps the platform's own). With `dns` the platform resolves through them only; each is also among `routes`. On a change of network the core calls `Apply` again with the same settings (`Refresh`), for platforms that copy the resolvers of the network below. Returns the tunnel's file descriptor. The same descriptor as last time keeps the device (iOS: the utun stays). A new one replaces it under the running reader (Android establishes a new interface on every change), and the core closes the old one. The core owns every descriptor it was given. |
| `Release()` | The overlay went down and the core closed the device. |
| `PublicKey()` | DER SubjectPublicKeyInfo of an ECDSA P-256 key. |
| `Sign(digest)` | Signs a SHA-256 digest, ASN.1 DER signature (`SecKeyCreateSignature` with `.ecdsaSignatureDigestX962SHA256`, Android `NONEwithECDSA`). The core asks for nothing else. |
| `KeyKind()`, `HardwareBound()` | `secure-enclave`, `android-keystore`, `android-strongbox`, … Like `hardware_bound` from a daemon this is the node's claim; an admin grants it and signs it into the binding (docs/TPM.md). |
| `Log(level, line)` | One text line per record, without a timestamp. Level as in `log/slog`. |

Changes are coalesced: bringing the overlay up, a hub advertising its
networks and tearing down each end in one `Apply` (50 ms quiet time), so
Android re-establishes once and not per route. Forwarding and NAT are refused:
an embedded node is an endpoint. Hubs, subnet routers and exit nodes run the
daemon.

The app's own sockets must stay outside the tunnel, or the control channel and
the hub links would try to go through themselves. Network extensions (iOS,
macOS) get that from the system. On Android the app excludes itself
(`addDisallowedApplication`). `excluded` is there for platforms that route by
address instead. A platform that gets this wrong breaks the connection; it
leaks nothing (SECURITY R104).

## API

```go
e, err := embed.Start(embed.Config{StateDir: dir, Platform: "ios", Name: "Ada's iPhone", AutoUp: true, MemoryLimitMiB: 40}, platform)
code, json := e.Request("GET", "/v1/status", nil) // every request of the daemon's socket (internal/node/ipc)
e.NetworkChanged()                                 // Wi-Fi <-> cellular: reconnect the control channel, retry hub links
e.Stop()
```

`Request` serves the daemon's socket API in memory with the same handler
(`ipc.Handler`, and `ipc.SetupHandler` while no control plane is configured).
The apps therefore speak one protocol and read one status JSON, whether they
talk to the Mac's daemon or to their own extension:

* `POST /v1/configure {"control_addr": "vpn.example.com"}`: the user enters
  the control plane once, and it is stored as `settings.json`.
* `POST /v1/enroll`, `/v1/up`, `/v1/down`, `/v1/login`,
  `GET /v1/login/{flow}`, `/v1/status`, `/v1/flows`, `/v1/profiles`.
* `POST /v1/reset` forgets the control plane. `new_identity` is refused: a new
  identity is a new key in the app's key store, so the app deletes its key and
  starts again.

`Config`:

| Field | |
|---|---|
| `state_dir` | Absolute path. On iOS and macOS the app group container, which app and extension share. |
| `platform` | Reported at enrollment (`ios`, `android`, `macos`). |
| `name` | Device name offered at enrollment. |
| `auto_up`, `profile` | The extension brings the overlay up once approved. It only runs while the user wants the tunnel. |
| `mtu` | Default 1280 (`transport.FitMTU`). |
| `control_pin`, `signers_genesis`, `hub_addrs`, `transport` | Provisioning, as in a daemon's configuration file (MDM). |
| `memory_limit_mib` | Soft Go heap limit (`debug.SetMemoryLimit`). An iOS packet tunnel is killed at 50 MiB. |
| `log_level`, `flow_log` | `flow_log` writes a line per connection. Flow records reach the control plane either way. |

## One engine per state directory

On iOS and macOS the app shows status, enrolls and logs in while no tunnel
runs, and the extension exists only while the tunnel does. Both run an engine
on the shared state directory, one at a time: `Start` takes an exclusive
`flock` on `state_dir/engine.lock` and fails with `ErrBusy` while the other
side holds it. The lock goes away with the process, also when iOS kills the
extension.

The app releases its engine before it starts the tunnel. When the tunnel
stops, it takes the engine back. On Android the `VpnService` runs in the app's
process: one engine, and the service only answers `Apply`.

## Lab: node-m

`cmd/boundgate-embedtest` is the Linux stand-in for a phone: it plays the
platform with a tun device by descriptor (`IFF_TUN|IFF_NO_PI`, what
`VpnService` hands out) and `ip(8)`, uses a software key through the `Sign`
callback, and serves the engine's requests on the daemon's socket, so
`boundgatectl` and the lab scripts drive it unchanged. Compose service
`node-m` (172.30.0.50) and e2e step 16 check that it:

* enrolls, is confirmed and signed, and logs in;
* gets address, MTU and routes on its device;
* reaches the target behind the hubs;
* loses the device on `down` and gets a new one on `up`.

Measured in the lab (2026-09-21): a 300 MB download through node-m ran at
about 107 MB/s, with at most 25 MiB RSS for the whole process and a heap limit
of 40 MiB.

## The C interface: libboundgate

`cmd/libboundgate` exports the engine as C functions for Swift and JNI. The
header is `cmd/libboundgate/boundgate.h`:

```c
int64_t bg_start(const char *config_json, const bg_platform *platform, char **err);
char   *bg_request(int64_t engine, const char *method, const char *path, const uint8_t *body, int32_t len, int32_t *status);
void    bg_network_changed(int64_t engine);
void    bg_stop(int64_t engine);
int32_t bg_utun_fd(void);   // network extension: the utun NetworkExtension opened for us
char   *bg_version(void);
void    bg_free(void *p);
```

`bg_platform` holds the callbacks (`apply`, `release`, `public_key`, `sign`,
`log`) and a `ctx` pointer. Strings the core returns are freed with `bg_free`.
Error strings a callback hands back through `char **err` are `malloc`ed by
the app and freed by the core.

`bg_utun_fd` finds the tunnel descriptor of a network extension the way
WireGuard's app does: NetworkExtension does not hand it out, but it is open in
the process, and only a utun control socket answers `UTUN_OPT_IFNAME`. The
app's `apply` callback calls it after `setTunnelNetworkSettings` completes.

`make test-lib` (part of `make test`) builds the C archive in the box and runs
`testdata/harness.c` against it: setup status, fingerprint of the platform's
key, the state lock, configure refused while the key refuses to sign, string
ownership, stop and restart.

## Not in M8.5

* Binding the core for the platforms: the xcframework for Apple (M8.6/M9a,
  `make apple-core`). Android loads the core as `libboundgate.so` with its
  JNI glue (ANDROID.md).
* Direct paths from an embedded node: it has no `paths.listen`. Peers reach it
  through relaying hubs, and it dials other nodes' public addresses as usual.
