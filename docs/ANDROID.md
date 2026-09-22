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
| `apps/android/app/src/main/kotlin/…` | `Core` (native methods), `Node` (the engine, requests, platform side), `DeviceKey` (Keystore), `TunnelService` (the `VpnService`), `MainActivity` and `Ui` (the screen). |
| `apps/android/Dockerfile` | SDK image (linux/amd64): JDK 21, SDK platform 36, build tools 36.1.0, NDK r29, Gradle 9.7.1, all pinned. Gradle builds the APK here. |
| `apps/android/Dockerfile.core` | Core image (native): Debian's clang and lld, Go 1.26.7, and from the SDK image the NDK's sysroot and compiler-rt. Builds `libboundgate.so`. |
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
* **Network changes:** the service follows the app's default network (the one
  under the VPN). When it changes, it tells the core (`NetworkChanged`: the
  control channel and hub links reconnect at once) and sets it as the VPN's
  underlying network, so Android reports metering correctly.
* **Disconnect:** `POST /v1/down`. The core closes the interface and calls
  `release`, and the service stops. If another VPN takes over or the user
  revokes it in the settings (`onRevoke`), the result is the same.
* **Always-on VPN:** the service declares `SUPPORTS_ALWAYS_ON`. The system
  starts it with the action `android.net.VpnService`, and after the process
  was killed it starts it again (`START_STICKY`). Both mean "connect".
* **Sign in:** the app opens the IdP's page in the browser and waits for the
  flow as the other apps do (`/v1/login`, `/v1/login/{flow}?wait=25s`).

## Always-on with "Block connections without VPN"

In this mode Android lets no app except BoundGate send anything outside the
tunnel, not even to the addresses the VPN excludes: the browser cannot reach
the IdP. Without a user session the hub refuses the tunnel (403), so the
sign-in would never get through.

The hub option `login_passthrough` solves it (off by default; SECURITY
R109):

```yaml
# hub
dns: [10.20.0.1]                        # resolvers for the apps (see "DNS" below)
login_passthrough: [136.243.123.200/32] # only for Android's lockdown mode: the IdP
```

With it, the hub admits a device without a session. Its tunnel carries only
flows to these destinations until the user has signed in. The app sees that
and still shows "Sign-in needed". In lockdown the app excludes nothing from
the tunnel (`isLockdownEnabled`), so the IdP and DNS go through the tunnel to
the passthrough. Without lockdown the app excludes them, and the option is
not needed.

DNS needs the hub's `dns` option in lockdown: nothing else is reachable
before the sign-in.

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
`dist/BoundGate-v0.1.6-unsigned.apk`, which the user signs with their own key:

```bash
apksigner sign --ks boundgate-release.jks --out BoundGate-v0.1.6.apk dist/BoundGate-v0.1.6-unsigned.apk
```

The version code is derived from the tag (`vX.Y.Z` → X·10000 + Y·100 + Z),
so each release installs over the one before it.

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
* **In-app update** via the signed manifest (RELEASES.md) and the APK in the
  release.
* A foreground notification needs the "system exempted" service type. If
  Android refuses it, the service runs without it: the system keeps a bound
  VPN service alive either way.
