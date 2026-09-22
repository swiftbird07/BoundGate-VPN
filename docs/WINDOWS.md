# BoundGate for Windows (M10)

On Windows the node runs as a service, the same daemon as on Linux and macOS.
The tray app is the frontend, like the Mac app for its LaunchDaemon. The
device key lives in the TPM.

Status 2026-09-21:

* Service, CLI and tray build for amd64 and arm64 in the box. Everything the
  platform does not decide is tested there: the route choice for host routes,
  the tray's phases and icon, the key selection.
* Not run on Windows yet. Acceptance is `deploy/windows/e2e.ps1` on the
  Proxmox VM with vTPM and on a PC (see "What is still open").

## Pieces

| Where | What |
|---|---|
| `cmd/boundgate-node` (`platform_windows.go`) | The service. `boundgate-node install [-config FILE]`, `uninstall`, `start`, `stop`. Under the service manager it runs until Stop or Shutdown. Started from a console it runs until Ctrl+C. |
| `internal/node/netcfg/netcfg_windows.go` | Wintun adapter through `wireguard/tun`. Address, MTU, routes and host routes through `winipcfg` (the IP Helper API, as in WireGuard for Windows). When the default routes outside the tunnel change (another Wi-Fi, a cable), the host routes to control plane and hubs are set again on the new path and the node reconnects (R108, the same on Linux and macOS). Endpoint only: forwarding and NAT are refused. |
| `internal/devicekey/tpm2key` (`device_windows.go`) | The existing TPM key over TPM Base Services (`go-tpm/…/windowstpm`). |
| `internal/node/ipc` (`protect_windows.go`) | The socket `%ProgramData%\BoundGate\node.sock` (AF_UNIX, Windows 10 1803 and later) with its own DACL. |
| `cmd/boundgate-tray`, `internal/tray` | The tray app. |
| `deploy/windows` | `install.ps1`, `uninstall.ps1`, `e2e.ps1`, the default `node.yaml`, `zip.sh`. |

## Paths

| | |
|---|---|
| Programs, `wintun.dll` | `%ProgramFiles%\BoundGate` |
| Configuration | `%ProgramData%\BoundGate\node.yaml` |
| State (TPM key blob, pins, settings) | `%ProgramData%\BoundGate\state` |
| Logs | `%ProgramData%\BoundGate\logs` |
| Socket | `%ProgramData%\BoundGate\node.sock` |

`%ProgramData%\BoundGate` gets a protected DACL: SYSTEM and Administrators
only, nothing inherited. By default every user may read ProgramData.

## Install

From the release zip `boundgate-<v>-windows-<arch>.zip`, in PowerShell as
administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -WintunZip $HOME\Downloads\wintun-0.14.1.zip
```

The tray icon appears right away. "Set up…" asks for the control plane's
address, then "Request access" shows its key for comparison. With
`-Control vpn.example.org` the address is set by the script, and
`boundgatectl enroll` works as well.

`install.ps1` does the following:

* Checks `wintun.dll`: Authenticode valid, signer WireGuard LLC.
* Copies the programs to Program Files.
* Creates the group `BoundGate Users` and adds the installing account.
* Writes `node.yaml` if none exists, and lists the installing account in
  `socket_users`: the group only reaches it at the next sign-in, the tray
  should work now.
* Registers and starts the service: automatic start, restart after 2, 5 and
  30 s on failure.
* Adds the tray to `HKLM\…\Run` and the program folder to `PATH`.
* Starts the tray in the user's session without administrator rights,
  through a one-time scheduled task (also when the script runs over ssh).

Running it again updates the programs. It keeps state, key and `node.yaml`.

`uninstall.ps1` removes everything except the state. `-Purge` removes the
state too, identity included; then revoke the node in the admin UI. At the
end it checks that no Wintun adapter is left.

Wintun is not in the zip. It is the one file from outside the release: its
license allows redistribution, but its signature is checked on the target
instead of trusting whatever the zip carries. Download it from
https://www.wintun.net.

## Device key

`key_kind: auto`, the Windows default, picks the TPM. Windows 11 requires a
TPM 2.0; a Proxmox VM needs a vTPM (`tpmstate0`, version 2.0). If there is no
TPM, the service does not start and says why in the event log
(Application, source BoundGate). `key_kind: softkey` is then a decision in `node.yaml`, not
a silent fallback, and the status carries a warning.

A node that enrolled with a software key keeps it. An identity in the TPM
stays in the TPM (`device.tpm`). The key is created in the owner hierarchy
under the SRK like on Linux (TPM.md). The blob in `state\device.tpm` is
useless on any other machine.

## Tray

The menu shows:

* The phase, as on the Mac: service not running, no access (sign out and
  in once), not set up, not enrolled, waiting for approval, disconnected,
  connecting, sign in required, connected.
* Set up…, when no control plane is configured: a small window for its
  address. The field lowercases what is typed (the control plane compares
  its name exactly), then the tray requests access.
* The icon's color: gray, amber, green or red.
* Connect and Disconnect. A profile submenu when there is more than one
  profile.
* Sign in (browser) and Sign out.
* Request access, with a key comparison for the first contact: the same
  text as `boundgatectl enroll`, "No" is the default.
* Details, closed until opened: address, hubs with protocol and bytes, the
  current rate, control plane and its protocol, adapter and MTU, key kind,
  fingerprint, version. Also "Copy fingerprint".

The tray holds no key and no secret. It talks to the socket as the signed-in
user, which works for members of `BoundGate Users` (`socket_group` in
`node.yaml`) and for the accounts in `socket_users`. The group only applies
after signing in again. Whoever may use the socket may also set the control
plane while none is set, like the Mac app's users.

## Updates

The service checks releases like everywhere else and shows "update
available". It does not install on Windows: that needs Authenticode signed
programs. Install the new zip with `install.ps1`, after checking it against
the release's signed `manifest.json` (RELEASES.md): the zip's SHA-256 is in
it.

## Acceptance

On the VM (vTPM) and on a PC, after install, configure and enroll with
admin approval:

```powershell
.\e2e.ps1 -Target 10.20.0.1 -Port 22
```

It checks these, and writes a transcript next to itself:

1. The service answers.
2. The key is `tpm2` and hardware-bound.
3. The node is approved and its binding verified.
4. `up` creates the adapter, address and routes, with sign-in if asked.
5. The target answers through the tunnel.
6. `down` leaves no adapter, and the routing table is what it was before.
7. After a service restart the node keeps its identity. With
   `auto_up: true` it connects again by itself.

By hand on a laptop: while connected, switch from Wi-Fi to a phone hotspot.
The tunnel should be back within seconds, and `route print` should show the
host route to the hub via the hotspot's gateway.

## What is still open

1. **Run it:** `e2e.ps1` on the Proxmox VM (vTPM) and on a PC. Then a
   policy with `hardware_bound`, a reboot with `auto_up: true`, and
   `uninstall.ps1`.
2. **DNS:** like the other platforms, the node sets no DNS. A split-DNS rule
   (NRPT) for overlay names comes with the DNS milestone.
3. **Stage 2:**
   * An MSI with Authenticode signatures, when there is a certificate. Until
     then SmartScreen warns (R106).
   * Self-installing updates.
   * An application manifest for the tray (DPI, common controls).
4. **Hub and subnet router on Windows:** not planned. Forwarding and NAT are
   refused.
