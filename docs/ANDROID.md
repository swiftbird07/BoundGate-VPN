# BoundGate for Android (M9b)

The Android app runs the same node as every other BoundGate device, embedded
(EMBED.md). The engine lives in the app's process. The `VpnService` lives in
the same process and only builds the tunnel interface when the core asks for
one. The device key is a P-256 key in the Android Keystore, in StrongBox where
the phone has one.

Status 2026-09-22: `make android` builds the APK (arm64 and x86-64, 16 KB aligned, Gradle checksums enforced); not yet run on a phone.

## Pieces

| Where | What |
|---|---|
| `cmd/libboundgate/jni_android.c` | JNI glue in the core's own library: the functions of `boundgate.h` as the native methods of `com.net407.boundgate.Core`, and the platform callbacks as calls on the app's `Core.Platform`. The app loads one library, `libboundgate.so`. |
| `apps/android/app/src/main/kotlin/…` | `Core` (native methods), `Node` (the engine, requests, platform side), `DeviceKey` (Keystore), `TunnelService` (the `VpnService`), `VpnTileService` (the Quick Settings tile), `MainActivity` and `Ui` (the screen). |
| `apps/android/Dockerfile` | SDK image (linux/amd64): JDK 21, SDK platform 36, build tools 36.1.0, NDK r29, Gradle 9.7.1, all pinned. Gradle builds the APK here. |
| `apps/android/Dockerfile.core` | Core image (native): Debian's clang and lld, Go 1.26.10, and from the SDK image the NDK's sysroot and compiler-rt. Builds `libboundgate.so`. |
| `apps/android/build.sh` | `make android`: vendors the Go modules in the box, builds the core for arm64 and x86-64 (emulator) in the core image, then the APK in the SDK image. |
| `apps/android/gradle/verification-metadata.xml` | SHA-256 of every plugin and library Gradle may load. |

The app uses only the platform's APIs (no AndroidX, no Compose), so Gradle
loads the Android Gradle Plugin, the Kotlin compiler and what they need, and
the APK carries only the Kotlin standard library besides the app itself.

## How it works

* **Engine:** started on first use with `state_dir` = the app's files
  directory, `platform: android`, and the device name from the system
  settings. `auto_up` stays off: the service brings the overlay up.
* **Connect:** the app asks for VPN consent (`VpnService.prepare`), starts
  `TunnelService` in the foreground, and the service sends `POST /v1/up`.
* **`apply`:** the service builds a new interface for every change
  (`Builder.establish`): the overlay address, the MTU and the routes, with
  0.0.0.0/0 as its two halves. It hands the descriptor over with `detachFd`,
  so the core owns it and closes the old one. It adds the DNS servers of the
  network below (apps in a VPN without DNS servers resolve nothing) and
  excludes their addresses and the `excluded` hosts from the tunnel
  (`excludeRoute`, Android 13, hence minSdk 33). The core coalesces changes, so
  a connect builds one interface, not one per route.
* **The app's own sockets** stay outside the tunnel
  (`addDisallowedApplication` for the app itself). That covers the control
  channel, the hub links and the IdP. The `excluded` hosts need no route
  here.
* **Network changes:** the service follows the best network that is not a
  VPN and has internet (`registerBestMatchingNetworkCallback`; the one
  under the VPN). When it changes, it tells the core (`NetworkChanged`: the
  control channel reconnects at once and the hub links move to new sockets
  by QUIC connection migration, POWER.md). The VPN's underlying network is
  left to Android (`setUnderlyingNetworks(null)`, called once: the system's
  default network, followed as it changes), so the status bar shows the
  network's icon and metering is right. Until 2026-10-28 the service used
  the app's default network callback and named that network as the
  underlying one; on a Samsung (Android 17) the callback reported only the
  VPN itself, so a move to Wi-Fi never reached the core and the VPN kept the
  dead network as its underlying one -- Wi-Fi joined, no icon, no internet
  until the VPN was switched off and on. The core then
  hands the settings over again; the interface is only built anew when
  something in them changed (the resolvers copied from the network below,
  lockdown), otherwise the one the core holds stays. Until 2026-10-26 every
  hand-over built a new interface, and one built while the phone was joining
  a Wi-Fi left it without internet -- the Wi-Fi joined, no icon, nothing
  reached the net -- until the VPN was switched off and on.

  Any network other than the one the core is on counts as a change, also
  the first one after a gap with none: walking out of a Wi-Fi, a switch from
  one Wi-Fi to another and airplane mode all arrive as `onLost` and then a
  new network. Until 2026-10-28 that new network passed as "the first one"
  and the core was not told; its tunnels stayed on sockets of a network
  that was gone until QUIC gave up on them. The same network becoming
  validated (Android confirmed that it reaches the internet) is passed on
  as well, so a dial that failed while the network was coming up is retried
  at once. A change of the resolvers below only matters while the VPN
  carries them (no hub `dns`).

  On the core's side a hub tunnel that is lost leaves its routes and
  resolvers standing for 30 s while the link dials again (`routeGrace`,
  spoke.go): withdrawing them and installing them again seconds later would
  be two new interfaces in a row, in the middle of the change of network.
  Meanwhile packets for those routes are dropped, as a VPN that is
  reconnecting should; a hub that refused the device withdraws at once.
* **Debug log** (menu ⋯ → *Debug log*): everything around the tunnel into
  a file under the app's storage -- the service's start and stop, every
  network callback with Android's own description of the network, every
  interface built or kept and why, the core's log at debug level including
  one line per connection, the node's status whenever it changes -- with
  the wall-clock time, the uptime (stops while the phone sleeps) and the
  elapsed real time (does not) on every line. *Share debug log* hands the
  file (4 MB, one older part kept) to any app through the app's own
  `LogProvider`; nothing else of the app's storage is reachable that way.
  Switching the log on sets the core to debug (`Core.setLogLevel`) and
  stays on across restarts of the app until it is switched off. The log
  names nodes, addresses, hubs and the signed-in user, never keys or
  tokens.
* **Route:** a "Route" row in the connection card whenever the node offers
  more than one profile ([PROFILES.md](PROFILES.md)): connected, the node
  switches at once (`POST /v1/profile`); otherwise the choice is kept in the
  app's preferences and the service brings the overlay up in it.
* **Disconnect:** `POST /v1/down`. The core closes the interface and calls
  `release`, and the service stops. If another VPN takes over or the user
  revokes it in the settings (`onRevoke`), the result is the same. When the
  core went down by itself and comes back on its own (its snapshot ran out
  while the control plane did not answer, R26; the status says `resuming`),
  the service stays: stopped, the overlay came back with no service to build
  its interface, and the app said "Connected" without a VPN. A stop only
  ends the service for the newest start request, so a Connect right after a
  Disconnect is not undone by it.
* **Quick Settings tile** (`VpnTileService`, add it by editing the panel):
  one tap connects or disconnects, as the app's button does. It reads the
  same status as the app: "Connected", "Connecting", "Sign-in needed" (all
  shown as on), "Off", or "Open the app" while the device is not set up or
  not approved. Connecting from the tile needs the VPN permission already
  given; the first time, and again after another VPN app took it over, the
  tile opens the app, which asks for it and connects. The same happens if
  Android refuses to start the service from the tile. The core's
  `statusChanged` asks the system to read the tile again whenever what it
  shows changes. The intents the tile and the sign-in notification send to
  the activity carry a token from the app's private preferences
  (`LaunchToken`): the activity is exported, so any app could send the same
  actions, and without the token they only open the app (R147).
* **Always-on VPN:** the service declares `SUPPORTS_ALWAYS_ON`. The system
  starts it with the action `android.net.VpnService`, and after the process
  was killed it starts it again (`START_STICKY`). Both mean "connect".
* **Sign in:** the app opens the IdP's page in the browser and waits for the
  flow as the other apps do (`/v1/login`, `/v1/login/{flow}?wait=25s`).
  When the session ends (24 h by default) the core tells the app
  (`statusChanged`) and it posts a notification "Sign-in needed" (channel
  "Sign-in", withdrawn once a hub is connected again); the activity asks
  for `POST_NOTIFICATIONS` on its first start.
* **Power save** is on (POWER.md): an idle tunnel sends a keep-alive every
  2 min, the snapshot is polled every 10 min and after every network
  change.

## Always-on with "Block connections without VPN"

In this mode Android lets no app except BoundGate send anything outside the
tunnel, not even to the addresses the VPN excludes: the browser's way to the
IdP runs through the tunnel like everything else.

That used to be a problem, because a hub refused a tunnel without a user
session and the sign-in could never get through; the hub option
`login_passthrough` existed for this one case. Since 2026-10-01 a session is
not a condition of the tunnel (OIDC.md), so the tunnel is there before the
sign-in and the option is gone. What the device may reach before it has a
user is a policy like any other:

```
permit(principal in BoundGate::Tag::"phone", action,
       resource == BoundGate::Host::"136.243.123.200");   // the IdP
```

```yaml
# hub
dns: [10.20.0.1]   # resolvers for the apps (see "DNS" below)
```

DNS needs the hub's `dns` option in lockdown: nothing else is reachable
before the sign-in. A hub lets DNS to the resolvers it offers through by
itself, so no policy is needed for that.

## DNS

A hub can offer resolvers (hub option `dns`, empty by default). It sends
them with the answer that opens the tunnel (`Boundgate-Dns` header, over the
hub's authenticated connection). The node takes those of its primary hub
and hands them to the app as `dns` in the network settings, together with a
route through the tunnel for each. The app then uses only these servers.
The hub lets DNS to them (port 53, UDP and TCP) through for every device,
also before the sign-in and whatever the policies say.

Without `dns` the app copies the resolvers of the network below and keeps
them outside the tunnel. In lockdown that fails (blocked outside the tunnel),
and so does a cellular network that hands out IPv6 resolvers only.

## Device key

`DeviceKey` creates `boundgate-device` in the `AndroidKeyStore`: EC P-256,
purpose sign, digests NONE and SHA-256. It tries StrongBox first and falls
back to the TEE when there is none or when it refuses the key.

The core only asks for signatures over SHA-256 digests. `NONEwithECDSA` over
the digest is ECDSA over the message (EMBED.md).

`KeyInfo.securityLevel` sets what the node claims at enrollment:

| Level | `key_kind` | `hardware_bound` |
|---|---|---|
| StrongBox | `android-strongbox` | yes |
| TEE | `android-keystore` | yes |
| software | `android-keystore-software` | no |

As on every platform, this is the node's claim. The admin grants it at
confirmation, and it only counts once signed into the binding (TPM.md).

The key cannot be exported or backed up. The app has `allowBackup="false"`,
so a restored phone starts as a new device. A new identity means deleting
the app's data or reinstalling the app.

## Building

```bash
make android
```

Why two images: Google ships the NDK and the build tools for x86-64 Linux
only, which on Apple silicon runs emulated. Gradle and aapt2 are fine that
way; the go command is not (it panicked under qemu, "import reader looping").
So Go runs natively and links with a native clang against the NDK's sysroot
and compiler-rt (`-rtlib=compiler-rt -unwindlib=libunwind`), with 16 KB page
alignment for Android 15 devices. The library needs only `libc`, `libdl` and
`liblog`.

This builds `dist/BoundGate-dev-debug.apk`. It is signed with the image's
debug key and can be installed with `adb install`. The first run builds the
image (about 2 GB of SDK and NDK, emulated on Apple silicon).

`make android VERSION=v0.1.6 ANDROID_BUILD=release` builds
`dist/BoundGate-v0.1.6-unsigned.apk`. The version code is derived from the tag
(`vX.Y.Z` → X·10000 + Y·100 + Z), so each release installs over the one
before it.

## Signing

`make release` does both: it builds the unsigned APK in these images and signs
it here, as it does the Mac app (RELEASES.md step 3). CI never sees the key.
`deploy/release/sign-apk.sh` is that step, and `--check` is what the release
asks before it pushes a tag.

**The certificate is the app's identity, for good.** Android installs an
update only when it carries the certificate of what is already installed, or a
successor the old key signed over to. There is no issuer who could replace a
lost key: lose it without a prepared successor and no phone that has the app
can ever be updated again — only uninstalling and installing anew helps.
Because of that the certificate is pinned in the repository
(`deploy/release/apk_cert_sha256`, written on the first release and compared on
every one after it), so a key you did not mean to use stops the release instead
of reaching a phone.

A keystore to sign with, once:

```bash
keytool -genkeypair -keystore private/boundgate-apk.jks -storetype PKCS12 -alias boundgate -keyalg EC -groupname secp256r1 -validity 10950 -dname "CN=BoundGate"
```

```bash
security add-generic-password -s boundgate-apk-keystore -a "$USER" -w
```

`private/` is git-ignored and masked in the box. The password comes from the
macOS keychain and reaches `apksigner` in one environment variable, so it is in
no command line. `APK_KS`, `APK_KS_PASS`, `APK_KEY_ALIAS` and `APKSIGNER`
override all of it; the script's header lists them.

**A key in hardware** works too — a YubiKey's PIV applet through
`APK_KS=NONE APK_KS_TYPE=PKCS11` with the provider options. Note what it costs:
APK Signature Scheme v3 supports **one** signer, not a set, so "several keys,
any one of them" — the way the release manifest and the admin key list work —
is not available here. The equivalent is a *successor* prepared while both keys
are in hand:

```bash
apksigner rotate --out private/apk_lineage.bin \
  --old-signer --ks private/a.jks --ks-key-alias boundgate \
  --new-signer --ks private/b.jks --ks-key-alias boundgate
```

Keep the lineage; if the first key is gone, sign with the second and
`APK_LINEAGE=private/apk_lineage.bin`. Android then follows the chain and
accepts the update. Without that, hardware turns a stolen-key risk into a
total-loss risk.

**Dependencies:**
* Gradle checks every file it loads against `verification-metadata.xml`.
* After changing a version in `build.gradle.kts`, run
  `ANDROID_VERIFY=write make android` and review the diff.
* Versions are pinned by hand and at least 14 days old (SECURITY R106):
  AGP 9.4.0 (2026-09-01), Kotlin 2.4.20 (2026-09-07), Gradle 9.7.1
  (2026-08-19).
* The Go modules come from the box, with its cooldown. The image builds with
  `GOPROXY=off`.

## What is still open

* **On a phone:** enroll with a StrongBox/TEE key, connect to pVPN over
  cellular, reach an LAN target, switch Wi-Fi ↔ LTE in under 5 s, Always-on.
* **Key attestation as evidence for the admin** (plan M9b, SECURITY R103):
  the attestation chain of the key, shown before signing. It needs a field in
  the enroll request and in the admin UI.
* **In-app update**: the APK is in the release and the signed manifest names
  it, but nothing on the phone acts on that yet. `internal/embed`, the engine
  the apps run, has no updater at all, and `update.Service.Install` can only
  install a macOS bundle. It needs the checking and downloading part in Go and
  `PackageInstaller` with `REQUEST_INSTALL_PACKAGES` in the app, where the
  user confirms.
* A foreground notification needs the "system exempted" service type. If
  Android refuses it, the service runs without it: the system keeps a bound
  VPN service alive either way.
