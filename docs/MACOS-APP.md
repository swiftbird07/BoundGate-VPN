# BoundGate for macOS: the app (M8, stage 1)

`BoundGate.app` is a menu-bar app in Swift in front of the same
`boundgate-node` daemon that M5 brought to the Mac (MACOS.md). The daemon
still does everything that matters: key, enrollment, tunnel, routes,
policy. The app installs it, shows what it is doing and offers the five
things a person does: join a network, show the fingerprint, connect, sign
in, disconnect.

```
BoundGate.app/Contents/
  MacOS/BoundGate                         the menu-bar app (SwiftUI, no dependencies)
  MacOS/boundgate-node, boundgatectl      the Go daemon and CLI (built in the box)
  Resources/node.yaml                     the daemon's configuration, part of the signed bundle
  Resources/AppIcon.icns                  drawn from the mark at build time
  Library/LaunchDaemons/<bundle id>.node.plist   (file name = Label)
```

Stage 2 (a Network Extension instead of a root daemon, so the tunnel shows
up under System Settings › VPN) is planned separately; nothing in the app's
UI depends on which of the two carries the packets.

## Build

```bash
apps/macos/build-app.sh          # or: make mac-app   → dist/BoundGate.app
```

Go is cross-compiled in the box as always; Swift, `iconutil` and `codesign`
run on the Mac (Xcode command line tools). The script signs inside out
(daemon, CLI, then the bundle) with the hardened runtime and picks the
identity itself: a *Developer ID Application* identity if the keychain has
one, else *Apple Development*, else ad hoc. `SIGN_IDENTITY=…` and
`BUNDLE_ID=…` (default `de.swiftbird.boundgate`) override.

| Signature | Good for |
|---|---|
| Apple Development | your own Macs; enough for the background service |
| Developer ID Application + notarization | anyone's Mac: `apps/macos/notarize.sh` submits the app, staples the ticket and builds a signed, notarized `dist/BoundGate-<version>.dmg`. It needs `xcrun notarytool store-credentials boundgate-notary …` once, run by you; the scripts never see a password |
| ad hoc (`-`) | looking at the UI; macOS refuses to register the service |

No entitlements and no provisioning profile are involved in stage 1, and
an individual developer account is sufficient.

## Install and first run

1. Copy `BoundGate.app` to `/Applications` and open it. It lives in the menu
   bar: two frames, the second one dashed while there is no connection, a
   dot when something waits for you.
2. **Install service**: the app registers the daemon with `SMAppService`.
   macOS asks for consent under *System Settings › General › Login Items &
   Extensions*; the app opens that pane. The daemon then runs as root, is
   restarted by launchd, and starts at boot.
3. **Which network?** Enter the address of the control plane
   (`bg.example.com`, optionally `:port`). The daemon stores it in
   `/var/db/boundgate/settings.json`.
4. **Request access**: the app shows the fingerprint of the control plane's
   key, which this Mac pins from now on (compare it if your administrator
   published it), and sends the enrollment request.
5. **Waiting for your administrator**: the fingerprint of this Mac in four
   rows of four groups, made for reading aloud. The administrator compares,
   confirms and signs (ENROLLMENT.md); the window updates by itself.
6. **Connect**. Interactive nodes need a user: the app opens the browser for
   the single sign-on and carries on when you are done. `Sign out`,
   `Forget this control plane…` and `Remove background service` are behind
   the gear.

Warnings of the daemon appear where they matter: a network that was not
routed because this Mac already lives in it (overlap guard), a refused
`up` because another VPN owns the overlay range, a control plane whose key
changed, an approval that does not verify.

## What changed in the daemon

* **Setup mode.** A configuration file without `control.addr` no longer
  fails: the daemon serves its socket with `state: "unconfigured"` and waits
  for `POST /v1/configure {control_addr, control_server_name?, name?}`
  (`boundgatectl configure -control HOST[:PORT]`). The address is validated,
  stored (0600) and the node starts without a restart. A configuration file
  that names the control plane stays final: `configure` and `reset` are
  refused there.
* **Reset.** `POST /v1/reset` (`boundgatectl reset`, only while down)
  removes the address, the pinned control-plane key and the pinned admin
  key list, and returns to setup mode. The device key stays. This is the way
  out of a mistyped address, which would otherwise be pinned forever. With
  `{"new_identity": true}` (`boundgatectl reset -new-identity`) the device key
  goes as well: the way from a software key to a Secure Enclave key.
* **App updates.** Replacing `BoundGate.app` does not restart its
  LaunchDaemon; the old process would run on from the deleted file. The
  daemon checks every 15 s whether its executable is still the file it was
  started from and, once the node is down, ends itself; launchd (`KeepAlive`)
  starts the new one. A node that is up is left alone until it is down.
* **Updates.** The daemon looks for signed releases and installs them on
  request (`GET /v1/update`, `POST /v1/update/check`, `POST /v1/update/apply`);
  the app shows "Update available" and "Check for Updates…"
  ([RELEASES.md](RELEASES.md)).
* **First contact.** "Request access" first shows the key the control plane
  presents; the daemon pins it only after "It matches"
  ([ENROLLMENT.md](ENROLLMENT.md)).
* **Device key.** The bundle's `node.yaml` says `key_kind: auto`: a key in the
  Secure Enclave on Macs that have one, through the bundled helper
  `Contents/MacOS/boundgate-sekey`; a Mac that already enrolled keeps its key
  ([SECURE-ENCLAVE.md](SECURE-ENCLAVE.md)).
* **`socket_group`.** The socket stays `0660 root`, now with a configurable
  group. The app's configuration says `admin`, so administrators of the Mac
  use the app (and `boundgatectl`) without `sudo`; standard users cannot.
* **Configuration lookup.** Without `-config` the daemon looks for
  `node.yaml` next to itself, then in `../Resources` (the bundle), then
  `/etc/boundgate/node.yaml`.

## Inside the app

`apps/macos` is a Swift package: `BoundGateKit` (socket client and models;
HTTP/1.0 over the unix socket with plain BSD sockets, because URLSession
cannot do unix sockets), `BoundGateUI` (theme from DESIGN.md, views, the app
model that polls `/v1/status` every two seconds and derives one of eleven
phases), `BoundGate` (the `MenuBarExtra`), and `bgtool`:

```bash
swift run --package-path apps/macos bgtool snap /tmp/snap    # every panel state, dark and light, as PNG
BOUNDGATE_SOCKET=… swift run --package-path apps/macos bgtool status
```

While connected, the card ends in a closed "Details" row (the choice is
remembered). Open, it shows what the daemon reports in `/v1/status`:

| Section | Rows | From |
|---|---|---|
| Traffic | received, sent (total and per second), packets | `hubs[].bytes_in/_out`, `packets_in/_out`, plus `paths[].bytes_in/_out`; the rate is the difference of two polls |
| Tunnel | protocol (`CONNECT-IP · HTTP/3 (QUIC)` or `… HTTP/1.1 (TCP)` on the fallback), hub address, tunnel device and MTU, standby hubs, direct and relayed paths, all routes | `hubs[].transport`, `interface`, `mtu`, `paths`, `routes` |
| Control plane | address, protocol (`HTTP/3 (QUIC)` or `HTTP/2 (TCP fallback)`), policies and snapshot version, open and denied connections | `control`, `control_transport`, `policies`, `snapshot_version`, `flows`, `flows_denied` |
| This Mac | device key, version | `key_kind`, `version` |

The counters are IP packets through the tunnel, counted by the daemon per hub
tunnel since that tunnel came up; a reconnect starts them again. A daemon
before v0.1.5 does not count, and the section says so instead of showing zeros.
`boundgatectl status` prints the same numbers.

The app works with any daemon on `/var/run/boundgate/node.sock`
(`BOUNDGATE_SOCKET` overrides), including one installed with
`deploy/macos/install.sh`; "Install service" is only offered when none
answers. The look follows DESIGN.md: charcoal and signal yellow, the mark as
tile and as menu-bar template image, rounded display face, flat surfaces,
yellow as fill and marker, orange for warnings.

## Paths

| | |
|---|---|
| State (device key, pins, settings) | `/var/db/boundgate` (root, 0700) |
| Socket | `/var/run/boundgate/node.sock` (`root:admin`, 0660) |
| Logs | `/var/log/boundgate/*.jsonl`, launchd's stderr in `/var/log/boundgate-node.log` |
| Profiles (optional) | `/Library/Application Support/BoundGate/profiles/*.yaml` (MACOS.md); without any, "Everything offered" |
| CLI | `/Applications/BoundGate.app/Contents/MacOS/boundgatectl` |

Removing: gear › *Remove background service*, then delete the app.

**"The background service does not answer" after replacing the app.** macOS
ties a registered daemon to the code signature of the app that registered it.
An app with another signature in the same place (seen when a build signed
with an *Apple Development* certificate was replaced by a *Developer ID* one)
leaves an entry launchd refuses to start: `launchctl print
system/de.swiftbird.boundgate.node` says `job state = spawn failed`,
`last exit code = 78: EX_CONFIG`, `needs LWCR update`, and the daemon's log
stays empty because it never runs. The card offers *Register the service
again* (unregister, register; older builds: gear › *Remove background
service*, then *Install service*). The node's identity and state are files
under `/var/db/boundgate` and are not touched. Updates between releases keep
the same Developer ID and are not expected to trigger this.
`/var/db/boundgate` is the device identity and stays until you delete it.

## Not verified yet

Built, signed (Apple Development) and started on macOS 26; socket client,
setup mode, configure and reset tested against a daemon; every panel state
rendered and looked at. **Not yet done on a real Mac by a person:**
registering the service through `SMAppService` and its consent dialog, and
the full click path from "Install service" to "Connected". Until that has
been done once, treat it as untested.

## Risks

See SECURITY.md R72–R75.
