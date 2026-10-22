# BoundGate for Windows (M10)

On Windows the node runs as a service, the same daemon as on Linux and macOS.
The tray app is the frontend, like the Mac app for its LaunchDaemon. The
device key lives in the TPM.

Status 2026-10-22:

* Service, CLI and tray build for amd64 and arm64 in the box. Everything the
  platform does not decide is tested there: the route choice for host routes,
  the tray's phases and icon, the key selection.
* The acceptance run `deploy/windows/e2e.ps1` passed all eight steps on the
  Proxmox VM with vTPM, first on 2026-09-22 (Tiny11, Windows 11 23H2) and
  again on 2026-10-22 with the resolver checks of step 5b. The VM is a node of
  the production network (`tinywin11-lab`).
* The resolver, measured on that run: the rule
  `BoundGate-BoundGate` holds `Name=.`, `GenericDNSServers=10.20.0.1`,
  `ConfigOptions=8`, `Version=2`, the adapter has the same resolver, a name
  only the overlay knows resolves (`jump-ssh.pve.lan`) and the rest of the
  world still does. `down` leaves no rule. A rule left behind by a daemon that
  never got to its teardown is removed by `boundgate-node -repair` with no
  service running (R144).
* Not yet: a regular Windows PC (Tiny11 is a stripped build), and the rest of
  "What is still open".

## Pieces

| Where | What |
|---|---|
| `cmd/boundgate-node` (`platform_windows.go`) | The service. `boundgate-node install [-config FILE]`, `uninstall`, `start`, `stop`. Under the service manager it runs until Stop or Shutdown. Started from a console it runs until Ctrl+C. |
| `internal/node/netcfg/netcfg_windows.go` | Wintun adapter through `wireguard/tun`. Address, MTU, routes and host routes through `winipcfg` (the IP Helper API, as in WireGuard for Windows). When the default routes outside the tunnel change (another Wi-Fi, a cable), the host routes to control plane and hubs are set again on the new path and the node reconnects (R108, the same on Linux and macOS). Endpoint only: forwarding and NAT are refused. |
| `internal/node/netcfg/dnswindows_windows.go` | The host's resolver while the overlay is up (`resolver: hub`, the default): the hub's resolvers on the Wintun adapter (`SetInterfaceDnsSettings` through `winipcfg`) **and** a name resolution policy rule for `.`, because the adapter alone does not settle it -- Windows asks the other adapters' resolvers in parallel and takes whichever answers first, which is the leak docs/ACL.md is about. `resolver: system` opts out, and a machine where it cannot be set keeps its own and says so in the status. |
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

`%ProgramData%\BoundGate` belongs to Administrators and has a protected
DACL: SYSTEM and Administrators only, nothing inherited. By default every
user may read ProgramData, and create directories in it: a standard user
who made `%ProgramData%\BoundGate` before the first install would own it,
and an owner can always change the permissions again. So
`boundgate-node protect` (install.ps1 runs it before it writes anything
there) creates the directory already protected, or takes an existing one
over only if SYSTEM, Administrators or TrustedInstaller own it and
everything in it, without links or junctions; it then sets owner and DACL
on every entry. Anything else is refused with the path and its owner:
look at it, remove the directory as administrator, run install.ps1 again.
The service checks owner and DACL of the directory at every start and
does not start otherwise (event log: "boundgate-node does not start");
running install.ps1 again repairs a directory that is merely unprotected.

## Install

In PowerShell as administrator:

```powershell
irm https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/windows/setup.ps1 | iex
```

`setup.ps1` is the Windows counterpart of the server's `setup.sh`. It finds
the latest release on GitHub and checks its `manifest.json` against the
release keys (`ssh-keygen -Y verify`, as `update.sh` does; the OpenSSH client
is part of Windows 10 1809 and later). It then checks the zip for this
machine's architecture against the manifest (size and SHA-256). If Wintun is
not installed yet, it downloads `wintun-0.14.1.zip` from www.wintun.net.
Finally it runs the release's `install.ps1`. Run again, it updates.
Environment variables instead of parameters: `BOUNDGATE_CONTROL` (the control
plane, else the tray asks), `BOUNDGATE_REF` (a tag instead of the latest
release), `BOUNDGATE_REPO`. The release keys come from GitHub at the
release's tag, like the script itself: the signature guards against a
swapped file, not against whoever controls the repository (R99).

By hand, from the release zip `boundgate-<v>-windows-<arch>.zip`, in
PowerShell as administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -WintunZip $HOME\Downloads\wintun-0.14.1.zip
```

The tray icon appears right away. "Set up…" asks for the control plane's
address, then "Request access" shows its key for comparison. With
`-Control vpn.example.org` the address is set by the script, and
`boundgatectl enroll` works as well.

`install.ps1` does the following:

* Checks Wintun: the zip's SHA-256 must be the one www.wintun.net publishes
  for `wintun-0.14.1.zip`
  (`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`, pinned
  in the script), and the DLL for this architecture in it must have a valid
  Authenticode signature whose subject has exactly `CN=WireGuard LLC` and
  `O=WireGuard LLC`. A DLL on its own is not accepted.
* Copies the programs to Program Files.
* Creates or checks `%ProgramData%\BoundGate` (`boundgate-node protect`,
  see Paths) before it writes anything into it.
* Creates the group `BoundGate Users` and adds the installing account.
* Writes `node.yaml` if none exists, and lists the installing account in
  `socket_users`: the group only reaches it at the next sign-in, the tray
  should work now.
* Registers and starts the service: automatic start, restart after 2, 5 and
  30 s on failure.
* Adds the tray to `HKLM\…\Run`, a "BoundGate" entry to the Start menu
  (to bring the tray back after "Quit") and the program folder to `PATH`.
* Starts the tray in the user's session without administrator rights,
  through a one-time scheduled task (also when the script runs over ssh).

Running it again updates the programs. It keeps state, key and `node.yaml`.

`uninstall.ps1` removes everything except the state. `-Purge` removes the
state too, identity included; then revoke the node in the admin UI. At the
end it checks that no Wintun adapter is left.

Wintun is not in the zip. It is the one file from outside the release: its
license allows redistribution, but it is checked on the target (hash of
the zip, signature of the DLL) instead of trusting whatever the release
zip would carry. Download it from https://www.wintun.net. A new Wintun
version means a new hash in install.ps1, taken from that page.

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

A click on the icon opens the panel, a flyout above the taskbar like the
Mac app's window (`internal/tray/panel.go` lays it out and paints it,
`cmd/boundgate-tray/panel_windows.go` is the window, text in Segoe UI with
ClearType). It follows DESIGN.md: the mark on its tile, a state pill, one
card for the phase (set up, request access, waiting with the fingerprint,
connected with address, hub and user, details on demand), the action that
matters as a button, and a footer with the device, "Sign out" and "Quit".
It follows the Windows light or dark app mode and closes when it loses the
focus. `boundgate-tray -render-panel DIR` writes every phase as PNG files
without a window, for whoever works on it.

The icon is the mark, in the taskbar's color (white on dark, near black on
light): both frames at full strength when connected, the second dimmed
otherwise, a yellow dot when something wants the user, a red one when
something is broken.

The right button opens the menu, which shows:

* The phase, as on the Mac: service not running, no access (sign out and
  in once), not set up, not enrolled, waiting for approval, disconnected,
  connecting, sign in required, connected.
* Set up…, when no control plane is configured: a small window for its
  address. The field lowercases what is typed (the control plane compares
  its name exactly), then the tray requests access.
* Connect and Disconnect. A "Route" submenu when there is more than one
  profile, by what each profile does ("LAN only", not `lan-only`). It is
  there while the node is up as well: picking a profile then changes the
  routes under the running tunnel ([PROFILES.md](PROFILES.md)).
* With more than one network ([NETWORKS.md](NETWORKS.md)) that submenu is
  called "Network" and its entries name both ("Work · Full"); in the panel
  the pills are grouped under each network's name. A profile of the network
  in use is applied live, a profile of another network switches the network
  and comes up in that profile.
* Add network…, below "Set up…": the address of the other control plane and
  what to call it, then the tray switches to it and asks for access there --
  this PC has a device key of its own in every network. Removing one is
  `boundgatectl network remove ID`; the tray does not offer it, because
  giving up a key is not a menu entry to hit by accident.
* Sign in (browser) and Sign out. When the session ends while the tray
  runs (24 h by default), a message box offers to sign in again, once per
  occasion.
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
6. The hub's resolvers are the machine's while the overlay is up: the status
   names them, `Get-DnsClientNrptPolicy` holds the rule for `.`, a name only
   the overlay's resolver knows resolves, and other names still do.
7. `down` leaves no adapter, no policy rule, and the routing table is what it
   was before. A rule of ours lives in the registry and would survive a
   reboot, so `boundgate-node -repair` removes the rules of adapters that are
   gone, with no service and no network (R144).
8. After a service restart the node keeps its identity. With
   `auto_up: true` it connects again by itself.

By hand on a laptop: while connected, switch from Wi-Fi to a phone hotspot.
The tunnel should be back within seconds, and `route print` should show the
host route to the hub via the hotspot's gateway.

## What is still open

1. **Run it on a PC:** `e2e.ps1` on a regular Windows 11 (the VM passed).
   Then, on both: a policy with `hardware_bound`, a reboot with
   `auto_up: true`, `uninstall.ps1`, and `setup.ps1` from scratch (written
   2026-10-14, not yet run on Windows).
2. **The resolver on a machine whose own network is elsewhere.** On the lab VM
   the hub's resolver (10.20.0.1) sits in the VM's own LAN, so a rule left
   behind there points at a resolver the machine can still reach without the
   tunnel: the sweep was measurable, the outage it prevents was not. A machine
   in another network makes that half visible, the way the Mac did.
3. **Stage 2:**
   * An MSI with Authenticode signatures, when there is a certificate. Until
     then SmartScreen warns (R106).
   * Self-installing updates.
4. **Hub and subnet router on Windows:** not planned. Forwarding and NAT are
   refused.
