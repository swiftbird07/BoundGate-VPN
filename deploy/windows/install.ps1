<#
.SYNOPSIS
  Installs or updates BoundGate on Windows (stage 1: zip + script, docs/WINDOWS.md).

.DESCRIPTION
  Run from the unpacked release zip in an elevated PowerShell:

    .\install.ps1 -WintunZip C:\Users\me\Downloads\wintun-0.14.1.zip [-Control vpn.example.org]

  * copies boundgate-node.exe, boundgatectl.exe, boundgate-tray.exe and
    wintun.dll to %ProgramFiles%\BoundGate (wintun.dll only from the zip with
    the published SHA-256, and with a valid signature of WireGuard LLC)
  * creates %ProgramData%\BoundGate (owner Administrators, SYSTEM and
    Administrators only; refuses one that somebody else owns anything in) with
    node.yaml, unless one exists
  * creates the local group "BoundGate Users" and adds you: its members may
    use the tray and boundgatectl without administrator rights
  * registers the service "BoundGate" (LocalSystem, automatic start, restart
    on failure) and starts it; the tray starts at every sign-in
  * with -Control, configures the control plane (boundgatectl configure)

  Running it again updates the programs and keeps state, key and node.yaml.
#>
[CmdletBinding()]
param(
    # wintun-0.14.1.zip from https://www.wintun.net, as downloaded (its SHA-256 is checked)
    [string]$WintunZip,
    # control plane address, host[:port]; later with `boundgatectl configure -control HOST` as well
    [string]$Control,
    # the Windows account that uses the tray (default: the one running this script)
    [string]$User = "$env:USERDOMAIN\$env:USERNAME",
    [string]$InstallDir = "$env:ProgramFiles\BoundGate"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in PowerShell as administrator.'
}
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { throw "unsupported architecture $env:PROCESSOR_ARCHITECTURE" } }
$exes = 'boundgate-node.exe', 'boundgatectl.exe', 'boundgate-tray.exe'
foreach ($e in $exes) {
    if (-not (Test-Path (Join-Path $here $e))) { throw "$e is missing next to install.ps1: run it from the unpacked release zip." }
}
$group = 'BoundGate Users'
$dataDir = Join-Path $env:ProgramData 'BoundGate'
$svc = Get-Service -Name BoundGate -ErrorAction SilentlyContinue

# --- Wintun: the one file from outside this release. The zip is pinned by the
# SHA-256 that https://www.wintun.net publishes for it, and the DLL in it must
# carry a valid Authenticode signature whose subject says exactly
# CN=WireGuard LLC and O=WireGuard LLC (a subject that merely contains the
# text, e.g. in another attribute, is not enough).
$wintunZipName = 'wintun-0.14.1.zip'
$wintunZipSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
function Get-SubjectValues([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$Key) {
    # one relative distinguished name per line; a value with special characters comes in quotes
    $Cert.SubjectName.Format($true) -split "`r?`n" | Where-Object { $_ -ne '' } | ForEach-Object {
        $k, $v = $_ -split '=', 2
        if ($null -ne $v -and $k.Trim() -ceq $Key) { $v.Trim().Trim('"') }
    }
}
$wintun = $null
$tmp = $null
if ($WintunZip) {
    if ($WintunZip -notlike '*.zip') {
        throw "-WintunZip takes $wintunZipName itself (its SHA-256 is pinned), not a DLL: download it from https://www.wintun.net"
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $WintunZip).Hash
    if ($hash -ne $wintunZipSha256) {
        throw "$WintunZip has SHA-256 $hash, not that of $wintunZipName ($wintunZipSha256). Download it from https://www.wintun.net only."
    }
    $tmp = Join-Path $env:TEMP ("boundgate-wintun-" + [guid]::NewGuid())
    Expand-Archive -LiteralPath $WintunZip -DestinationPath $tmp
    $wintun = Join-Path $tmp "wintun\bin\$arch\wintun.dll"
    if (-not (Test-Path -LiteralPath $wintun)) { throw "no wintun.dll for $arch in $WintunZip" }
    $sig = Get-AuthenticodeSignature -LiteralPath $wintun
    $o = @(); $cn = @()
    # @(): a function's single result arrives as a scalar, and 'x'[0] is a character
    if ($sig.SignerCertificate) { $o = @(Get-SubjectValues $sig.SignerCertificate 'O'); $cn = @(Get-SubjectValues $sig.SignerCertificate 'CN') }
    if ($sig.Status -ne 'Valid' -or $sig.SignatureType -ne 'Authenticode' -or
        $o.Count -ne 1 -or $o[0] -cne 'WireGuard LLC' -or $cn.Count -ne 1 -or $cn[0] -cne 'WireGuard LLC') {
        throw "wintun.dll is not signed by WireGuard LLC (status $($sig.Status), signer $($sig.SignerCertificate.Subject)). Download it from https://www.wintun.net only."
    }
    Write-Host "wintun.dll: $wintunZipName (SHA-256 checked), signed by WireGuard LLC, version $((Get-Item -LiteralPath $wintun).VersionInfo.FileVersion)"
} elseif (-not (Test-Path (Join-Path $InstallDir 'wintun.dll'))) {
    throw "Wintun is needed once: download $wintunZipName from https://www.wintun.net and pass it with -WintunZip."
}

# --- programs
if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host 'stopping the service for the update'
    Stop-Service -Name BoundGate
}
Get-Process -Name boundgate-tray -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($e in $exes) { Copy-Item -Force (Join-Path $here $e) $InstallDir }
if ($wintun) { Copy-Item -Force $wintun (Join-Path $InstallDir 'wintun.dll') }
if ($tmp) { Remove-Item -Recurse -Force $tmp }
# Program Files is writable for administrators only, which keeps the service's
# executable (it runs as SYSTEM) out of reach of a standard user.

# --- group for the tray
if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $group -Description 'May use BoundGate without administrator rights' | Out-Null
    Write-Host "created group $group"
}
if (-not (Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $User })) {
    Add-LocalGroupMember -Group $group -Member $User
    Write-Host "added $User to $group (takes effect at the next sign-in)"
}

# --- configuration and service
# Before anything is written into it: %ProgramData%\BoundGate is created
# protected (owner Administrators, SYSTEM and Administrators only), or, if it
# exists, taken over only when nobody but SYSTEM, Administrators or
# TrustedInstaller owns anything in it; links and junctions are refused.
# A standard user may create directories in ProgramData, and the owner of a
# directory can always change its permissions again.
$node = Join-Path $InstallDir 'boundgate-node.exe'
& $node protect
if ($LASTEXITCODE -ne 0) { throw "$dataDir is not safe to use (the reason is above); nothing was written into it" }
$cfg = Join-Path $dataDir 'node.yaml'
if (-not (Test-Path $cfg)) {
    Copy-Item (Join-Path $here 'node.yaml') $cfg
    Write-Host "wrote $cfg"
} else {
    Write-Host "kept $cfg"
}
# the group reaches this account at its next sign-in only: until then it may
# use the socket by name, so the tray works right away
if (-not (Select-String -Path $cfg -Pattern '^socket_users:' -Quiet)) {
    Add-Content -Path $cfg -Value "socket_users: ['$($User -replace "'", "''")']   # may use the tray before signing in again (install.ps1)"
    Write-Host "allowed $User to use the service now"
}
if (-not $svc) {
    & $node install -config $cfg
    if ($LASTEXITCODE -ne 0) { throw 'service installation failed' }
}
Start-Service -Name BoundGate
Write-Host 'service BoundGate running'

# --- PATH, tray at sign-in
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($path -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$InstallDir", 'Machine')
    Write-Host "added $InstallDir to PATH (new shells)"
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'BoundGate' -Value "`"$InstallDir\boundgate-tray.exe`""
# a Start menu entry for every account: to bring the tray back after "Quit"
$lnk = New-Object -ComObject WScript.Shell
$sc = $lnk.CreateShortcut((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\BoundGate.lnk'))
$sc.TargetPath = Join-Path $InstallDir 'boundgate-tray.exe'
$sc.Description = 'BoundGate: status, connect, sign in'
$sc.Save()

# --- control plane
$ctl = Join-Path $InstallDir 'boundgatectl.exe'
for ($i = 0; $i -lt 30; $i++) {
    & $ctl status *> $null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 1
}
if ($Control) {
    & $ctl configure -control $Control
    if ($LASTEXITCODE -ne 0) { throw 'configure failed' }
    # the service leaves its setup mode and starts the node: wait for that,
    # or the status below would still say "unconfigured"
    for ($i = 0; $i -lt 15; $i++) {
        $st = & $ctl -json status 2>$null | Out-String | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($st -and $st.state -ne 'unconfigured') { break }
        Start-Sleep -Seconds 1
    }
}
& $ctl status

# --- the tray, now: in the user's session and without administrator rights
# (this script runs elevated, maybe over ssh); a one-time task does that
$task = 'BoundGate tray start'
try {
    $action = New-ScheduledTaskAction -Execute (Join-Path $InstallDir 'boundgate-tray.exe')
    $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Start-Sleep -Seconds 2
    # the task may already be gone once it ran: nothing to report then
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "started the tray for ${User}: the BoundGate icon is in the notification area (maybe behind ^)"
} catch {
    Write-Warning "could not start the tray now ($($_.Exception.Message)); it starts at the next sign-in"
}

Write-Host ''
Write-Host 'Next:'
$st = & $ctl -json status 2>$null | Out-String | ConvertFrom-Json -ErrorAction SilentlyContinue
if ($st -and $st.state -eq 'unconfigured') { Write-Host '  the tray icon: Set up... (the control plane address), then Request access' }
else { Write-Host '  the tray icon: Request access (compare the control pin with your administrator''s), or boundgatectl enroll' }
Write-Host '  then, once approved: Connect in the tray, or boundgatectl up'
