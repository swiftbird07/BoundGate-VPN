BoundGate for Windows
=====================

Install (PowerShell as administrator, in this folder):

  1. Download wintun-0.14.1.zip from https://www.wintun.net
  2. Set-ExecutionPolicy -Scope Process Bypass
  3. .\install.ps1 -WintunZip <path to wintun-0.14.1.zip> -Control <your control plane>
  4. boundgatectl enroll
     Compare the control plane key it shows with the one your administrator
     gave you. Then give your administrator the device fingerprint.
  5. Once approved: the BoundGate icon in the notification area (sign out and
     in once, so that the group "BoundGate Users" applies), or boundgatectl up

Remove: .\uninstall.ps1 (add -Purge to delete the device identity too)

These programs are not code-signed yet: Windows SmartScreen may warn. Check
the zip against the release's signed manifest.json first (docs/RELEASES.md).

More: docs/WINDOWS.md in the BoundGate repository.
