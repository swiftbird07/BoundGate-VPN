# BoundGate for Android (M9b)

The Android app runs the same node as every other BoundGate device, embedded
(EMBED.md). The engine lives in the app's process. The `VpnService` lives in
the same process and only builds the tunnel interface when the core asks for
one. The device key is a P-256 key in the Android Keystore, in StrongBox where
the phone has one.

Status 2026-09-22: built in the container, not yet run on a phone.

## Pieces

| Where | What |
|---|---|
| `cmd/libboundgate/jni_android.c` | JNI glue in the core's own library: the functions of `boundgate.h` as the native methods of `com.net407.boundgate.Core`, and the platform callbacks as calls on the app's `Core.Platform`. The app loads one library, `libboundgate.so`. |
| `apps/android/app/src/main/kotlin/…` | `Core` (native methods), `Node` (the engine, requests, platform side), `DeviceKey` (Keystore), `TunnelService` (the `VpnService`), `MainActivity` and `Ui` (the screen). |
| `apps/android/Dockerfile` | Build image: JDK 21, SDK platform 36, build tools 36.1.0, NDK r29, Gradle 9.7.1, Go 1.26.7, all pinned. |
| `apps/android/build.sh` | `make android`: vendors the Go modules in the box, builds the core for arm64 and x86-64 (emulator) and then the APK, both in the image. |
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
  so the core owns it and closes the old one. The core coalesces changes, so
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
