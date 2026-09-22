# BoundGate for iOS (M9a)

The iOS app runs the same node as every other BoundGate device, embedded
(EMBED.md): in the app while no tunnel runs, and in a packet tunnel extension
while the user wants the VPN. The device key is a P-256 key in the Secure
Enclave.

Status 2026-09-21:

* The core builds (`make apple-core`, 2026-09-22, go1.26.7 in
  `~/.local/go-apple`).
* App and extension link against it for devices and Apple silicon
  simulators.
* In the simulator the app starts its own engine, creates the device key (a
  software key there) and shows the setup screen. The simulator has no
  Network Extension service: loading the VPN configuration fails with "IPC
  failed", so the tunnel itself only runs on a device.
* Not run on an iPhone yet: that needs provisioning profiles and a device
  (see "What is still open").

## Pieces

| Where | What |
|---|---|
| `apps/ios/project.yml` | xcodegen spec. Targets `BoundGateiOS` (the app, product name BoundGate) and `BoundGateTunnel` (the `NEPacketTunnelProvider` extension). `make ios-project` writes `apps/ios/BoundGate.xcodeproj` (not committed). |
| `apps/ios/Shared` | Compiled into both targets. `CoreEngine` (Swift over `boundgate.h`: callbacks, requests, stop), `DeviceKey` (Secure Enclave key in the shared keychain group), `AppConfig` (identifiers from the Info.plist). |
| `apps/ios/Tunnel` | `PacketTunnelProvider`, described below. |
| `apps/ios/App` | The app entry, `TunnelController` (VPN configuration, the app's own engine, switching to the tunnel's) and `ProviderTransport`. |
| `apps/macos` package | `BoundGateKit` (models, `DaemonClient` over a `NodeTransport`) and `BoundGateUI` (theme, cards, `DetailsView`, and for iOS `MobileModel` + `MobileView`). The Mac app and the iOS app share them. |
| `build/apple/BoundGateCore.xcframework` | The node from Go (`cmd/libboundgate`), built by `make apple-core`. |

What `PacketTunnelProvider` does:

* It starts the engine with `auto_up` and a 30 MiB Go heap limit.
* It answers `apply` with `setTunnelNetworkSettings`: the overlay address,
  the included routes, the excluded host routes for control plane, hubs and
  IdP, and the MTU, and the hub's resolvers when it offers some (`dns`,
  for every name). It then hands the core the utun (`bg_utun_fd`).
* It ends the VPN when the node's overlay goes down.
* It forwards app messages to the node and reports its memory.

## Identifiers

They follow the Mac app and are set once in `project.yml`:

| | |
|---|---|
| App | `de.swiftbird.boundgate` |
| Packet tunnel | `de.swiftbird.boundgate.tunnel` |
| App group (state directory `boundgate/` in its container) | `group.de.swiftbird.boundgate` |
| Keychain group (device key) | `$(AppIdentifierPrefix)de.swiftbird.boundgate.shared` |
| Team, signing | `35RRDYK76R`, automatic |

Both targets need these capabilities in the developer portal, and Xcode
creates the profiles with automatic signing:

* App Groups
* Keychain Sharing
* Network Extensions (Packet Tunnel)

## How it runs

* **Tunnel off.** The app runs its own engine on the shared state directory.
  It can show status, save the control plane, enroll with pin comparison, sign
  in and out, and forget. `apply` is refused: routing is the extension's job.
* **Connect.** The app saves the VPN configuration. The first time, iOS asks
  "Add VPN Configurations". The app then stops its engine, which releases the
  directory lock, and starts the tunnel.
* **Tunnel on.** The extension's engine holds the directory. The app's
  requests (`GET /v1/status`, `POST /v1/login`, …) go to it as provider
  messages. `GET /x/memory` answers the extension's `phys_footprint`, and the
  app shows it under Details as "Tunnel memory: x of 50 MiB".
* **Start fails.** If the overlay does not come up within 25 seconds (not
  approved, control plane unreachable), the tunnel ends with the node's own
  explanation.
* **Disconnect.** The tunnel stops and releases the lock. The app takes its
  engine back and retries while the lock is still held.
* **Wi-Fi ↔ cellular.** `NWPathMonitor` and `wake()` call
  `bg_network_changed`.
* **Names.** Once the tunnel's DNS settings are in effect, the system
  resolver answers the extension's own lookups with "no such host" (seen on
  iOS 26 with the control plane's name, two hours into a tunnel: the tunnel
  kept running, the control channel did not, and the node showed as offline
  in the admin UI). The node therefore keeps an address book
  (`internal/node/resolve.go`): every name of the control plane, the hubs,
  peers and the identity provider is dialed by the address it resolved to,
  which is also the address excluded from the tunnel. A lookup that fails
  keeps the address the name had, with one warning in the log, and the next
  lookup that works replaces it. The same code runs on every platform.
* **IPv6-only networks.** Many mobile networks give a phone no IPv4 at all;
  an IPv4 address then fails at once with "network is unreachable" (UDP and
  TCP). Of a name's addresses the node dials the first the device has a
  route for, IPv4 first; on such a network that is the address the
  network's DNS64 answers with, and an IPv4 address without one (a literal,
  or a name whose lookup fails inside the tunnel) is translated with the
  network's NAT64 prefix, which the node asks for as `ipv4only.arpa`
  (RFC 7050, /96 prefixes). The prefix is asked for again after every
  network change. IPv6 is not routed into the tunnel, so those dials need
  no excluded route.
* **Joining a network a peer announces.** On mobile data the tunnel routes
  every network the hubs advertise, also a home LAN behind a subnet router.
  Joining that LAN's Wi-Fi then put the Wi-Fi's router, DHCP and DNS into
  the tunnel, and iOS refused to switch to it. The overlap guard (a network
  the machine is in is not routed) now runs again on every network change
  and whenever the machine's own addresses change (checked every 2 s), so
  the route leaves the tunnel within about a second of the address; leaving
  the network brings it back.
* **Enrollment across starts.** The node keeps the last enrollment state
  the control plane reported (`enrollment.json`) and shows it at once after
  a start, marked `enrollment_stale` until the control plane answers. It
  decides nothing: the overlay still needs a snapshot, which only an
  approved node gets. Before, the app showed "Request access" until the
  first answer, and for good when the control plane was unreachable.

The device key is created by the app on first start and only loaded by the
extension. Its access control is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
with `.privateKeyUsage` and no user presence, so the tunnel can reconnect
while the phone is locked. The simulator has no Secure Enclave: there the key
is a software key and is reported as `softkey`, not hardware-bound.

## Building the core

`make apple-core` runs `apps/ios/core/build.sh`:

* `box go mod vendor`: the modules come from the box and its cooldown, so the
  Mac needs no module proxy.
* It builds C archives with the Go toolchain in `~/.local/go-apple`:
  iOS arm64, iOS simulator arm64, and macOS arm64+x86_64.
* It adds `boundgate.h` with a module map that links `resolv`, `Security` and
  `CoreFoundation`, and runs `xcodebuild -create-xcframework`.

This is the one place Go runs on the Mac instead of the box (decided
2026-09-21). The toolchain is the official go.dev tarball in the same version
as the box, checked against its published SHA-256 and not on `PATH`.

Installing the toolchain (done once, 2026-09-22):

```bash
curl -fLO https://go.dev/dl/go1.26.7.darwin-arm64.tar.gz
```

```bash
/usr/bin/openssl dgst -sha256 -r go1.26.7.darwin-arm64.tar.gz
```

Compare the hash with the one on go.dev/dl, then:

```bash
mkdir -p ~/.local/go-apple.tmp && tar -C ~/.local/go-apple.tmp -xzf go1.26.7.darwin-arm64.tar.gz && mv ~/.local/go-apple.tmp/go ~/.local/go-apple
```

A new Go version in the box means the same version here.

## Building the app

```bash
make apple-core
```

```bash
make ios-project
```

```bash
open apps/ios/BoundGate.xcodeproj
```

Then run the `BoundGateiOS` scheme on the iPhone. For a compile check without
signing:

```bash
xcodebuild -project apps/ios/BoundGate.xcodeproj -scheme BoundGateiOS -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

An unsigned build starts and says that the device key is not reachable: it
has no keychain group. Everything real needs the signed build.

## The tunnel's log

The packet tunnel also writes its log to `Documents/tunnel.log` in its own container
(`tunnel.log.1` is the one before, 1 MiB each). The file holds the core's
lines, every path the system reports (`path:`, the full description with
interfaces and gateways) and every set of settings handed to the system
(`apply:`). From a development build, with the phone connected:

```bash
xcrun devicectl device copy from --device <id> --domain-type appDataContainer --domain-identifier de.swiftbird.boundgate.tunnel --source Documents/tunnel.log --destination tunnel.log
```

`xcrun devicectl list devices` shows the id.

## What is still open

1. **Profiles:** open the project in Xcode once with the team signed in, and
   let automatic signing register the App IDs, the app group and the Network
   Extension capability.
2. **Memory spike on the iPhone** (the plan's gate before more UI work):
   connect, run a speed test through the tunnel, and read "Tunnel memory"
   under Details. The goal is below 35 MiB of the 50. In the lab the embedded
   engine stayed at 25 MiB RSS for 300 MB (EMBED.md).
3. **Acceptance:** enroll with the Secure Enclave key, get confirmed and
   signed, sign in, connect to pVPN, and reach the LAN target. Check a policy
   with `hardware_bound`, and a Wi-Fi ↔ LTE switch in under 5 s.
4. Later:
   * App icon asset. The app has none yet.
   * On-demand rules.
   * Distribution: TestFlight internal, and the App Store needs an
     organization account.
   * Sharing one dynamic framework between app and extension instead of
     linking the core into both.
