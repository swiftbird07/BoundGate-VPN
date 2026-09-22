<#
.SYNOPSIS
  Removes BoundGate from Windows.

.DESCRIPTION
  Run in an elevated PowerShell. Disconnects, removes the service, the tray
  autostart, the programs, the PATH entry and the group "BoundGate Users".
  The node's state (device key, pins, settings) in %ProgramData%\BoundGate
  stays unless -Purge is given; a TPM key's blob is useless without this
  TPM, but its identity is still approved until an administrator revokes it.

  At the end it checks that no BoundGate adapter and no route over one is
  left behind.
#>
[CmdletBinding()]
param(
    [switch]$Purge,
    [string]$InstallDir = "$env:ProgramFiles\BoundGate"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in PowerShell as administrator.'
}
$ctl = Join-Path $InstallDir 'boundgatectl.exe'
$node = Join-Path $InstallDir 'boundgate-node.exe'
if ((Get-Service -Name BoundGate -ErrorAction SilentlyContinue) -and (Test-Path $ctl)) {
    & $ctl down *> $null   # routes and host routes are removed by the node itself
}
Get-Process -Name boundgate-tray -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service -Name BoundGate -ErrorAction SilentlyContinue) {
    & $node uninstall
    if ($LASTEXITCODE -ne 0) { throw 'removing the service failed' }
}
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'BoundGate' -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\BoundGate.lnk') -ErrorAction SilentlyContinue
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$kept = ($path -split ';') | Where-Object { $_ -and $_ -ne $InstallDir }
[Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
if (Get-LocalGroup -Name 'BoundGate Users' -ErrorAction SilentlyContinue) { Remove-LocalGroup -Name 'BoundGate Users' }
$data = Join-Path $env:ProgramData 'BoundGate'
if ($Purge -and (Test-Path $data)) {
    Remove-Item -Recurse -Force $data
    Write-Host "removed $data (device identity included; revoke the node in the admin UI)"
} elseif (Test-Path $data) {
    Write-Host "kept $data (device identity; remove with -Purge)"
}

# nothing may stay behind in the network configuration
$left = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like 'Wintun*' -or $_.Name -eq 'BoundGate' })
if ($left.Count -gt 0) {
    Write-Warning ("adapter left behind: " + ($left.Name -join ', '))
    exit 1
}
Write-Host 'BoundGate removed; no adapter left.'
