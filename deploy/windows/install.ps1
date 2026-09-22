<#
.SYNOPSIS
  Installs or updates BoundGate on Windows (stage 1: zip + script, docs/WINDOWS.md).

.DESCRIPTION
  Run from the unpacked release zip in an elevated PowerShell:

    .\install.ps1 -WintunZip C:\Users\me\Downloads\wintun-0.14.1.zip [-Control vpn.example.org]

  * copies boundgate-node.exe, boundgatectl.exe, boundgate-tray.exe and
    wintun.dll to %ProgramFiles%\BoundGate (wintun.dll only after its
    Authenticode signature was checked: WireGuard LLC)
  * creates %ProgramData%\BoundGate (SYSTEM and Administrators only) with
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
    # wintun-0.14.1.zip from https://www.wintun.net (or the wintun.dll for this machine's architecture)
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

# --- Wintun: the one file from outside this release; checked by its signature
$wintun = $null
$tmp = $null
if ($WintunZip) {
    if ($WintunZip -like '*.zip') {
        $tmp = Join-Path $env:TEMP ("boundgate-wintun-" + [guid]::NewGuid())
        Expand-Archive -Path $WintunZip -DestinationPath $tmp
        $wintun = Join-Path $tmp "wintun\bin\$arch\wintun.dll"
    } else {
        $wintun = $WintunZip
    }
    if (-not (Test-Path $wintun)) { throw "no wintun.dll for $arch in $WintunZip" }
    $sig = Get-AuthenticodeSignature -FilePath $wintun
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=WireGuard LLC') {
        throw "wintun.dll is not signed by WireGuard LLC (status $($sig.Status), signer $($sig.SignerCertificate.Subject)). Download it from https://www.wintun.net only."
    }
    Write-Host "wintun.dll: signed by WireGuard LLC, version $((Get-Item $wintun).VersionInfo.FileVersion)"
} elseif (-not (Test-Path (Join-Path $InstallDir 'wintun.dll'))) {
    throw 'Wintun is needed once: download wintun-0.14.1.zip from https://www.wintun.net and pass it with -WintunZip.'
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
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$cfg = Join-Path $dataDir 'node.yaml'
if (-not (Test-Path $cfg)) {
    Copy-Item (Join-Path $here 'node.yaml') $cfg
    Write-Host "wrote $cfg"
} else {
    Write-Host "kept $cfg"
}
$node = Join-Path $InstallDir 'boundgate-node.exe'
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
}
& $ctl status

Write-Host ''
Write-Host 'Next:'
if (-not $Control) { Write-Host "  boundgatectl configure -control HOST" }
Write-Host '  boundgatectl enroll          (compare the control pin with your administrator''s)'
Write-Host '  then, once approved: the tray icon (sign out and in once for the group), or boundgatectl up'
