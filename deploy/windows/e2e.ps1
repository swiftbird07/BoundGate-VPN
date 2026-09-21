<#
.SYNOPSIS
  M10 acceptance on a Windows machine (the Proxmox VM with vTPM, or a PC).

.DESCRIPTION
  Run in an elevated PowerShell after install.ps1, with the node configured
  (boundgatectl configure -control HOST) and enrolled:

    .\e2e.ps1 -Target 10.20.0.1 -Port 22

  Checks, in order:
    1. the service runs and answers on its socket
    2. the device key is in the TPM and reported hardware-bound
    3. the node is approved and its signed binding verified
    4. up: the Wintun adapter, its address and routes appear; sign-in if
       the hubs want one (opens the URL for you)
    5. the target behind the network answers through the tunnel
    6. down: no adapter, no route over it, no host route left behind; the
       routing table is what it was before
    7. restart of the service: it comes back, keeps its identity, and (with
       auto_up: true in node.yaml) connects again by itself

  Writes a transcript to e2e-<time>.log next to this script. Changes nothing
  except bringing the tunnel up and down and restarting the service.
#>
[CmdletBinding()]
param(
    # an address behind the hub (pVPN: a LAN host) that answers on -Port
    [Parameter(Mandatory = $true)][string]$Target,
    [int]$Port = 443,
    # the profile to connect with (default: the node's)
    [string]$NodeProfile = '',
    # accept a software key (a machine without a TPM); the key check then only warns
    [switch]$AllowSoftkey,
    [string]$InstallDir = "$env:ProgramFiles\BoundGate"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Start-Transcript -Path (Join-Path $here ("e2e-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')) | Out-Null
$ctl = Join-Path $InstallDir 'boundgatectl.exe'
$script:failed = $false

function Fail([string]$msg) { Write-Host "FAIL: $msg" -ForegroundColor Red; $script:failed = $true; throw $msg }
function Pass([string]$msg) { Write-Host "ok:   $msg" -ForegroundColor Green }
function Status {
    $out = & $ctl -json status 2>&1
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($out | Out-String | ConvertFrom-Json)
}
function WaitFor([int]$seconds, [scriptblock]$cond) {
    for ($i = 0; $i -lt $seconds; $i++) {
        $s = Status
        if ($s -and (& $cond $s)) { return $s }
        Start-Sleep -Seconds 1
    }
    return $null
}
function Has($obj, [string]$name) { return $obj.PSObject.Properties.Name -contains $name -and $null -ne $obj.$name }
function RouteTable {
    Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -notlike 'ff00::*' -and $_.DestinationPrefix -notlike 'fe80::*' } |
        ForEach-Object { "$($_.DestinationPrefix) via $($_.NextHop) if $($_.InterfaceAlias)" } | Sort-Object -Unique
}

try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'run this in PowerShell as administrator' }

    Write-Host '== 1. service'
    $svc = Get-Service -Name BoundGate -ErrorAction SilentlyContinue
    if (-not $svc) { Fail 'service BoundGate not installed (install.ps1)' }
    if ($svc.Status -ne 'Running') { Fail "service BoundGate is $($svc.Status)" }
    $s = Status
    if (-not $s) { Fail 'boundgatectl status does not answer' }
    if ($s.state -eq 'unconfigured') { Fail 'no control plane configured: boundgatectl configure -control HOST' }
    Pass "service runs, version $($s.version), control plane $($s.control)"
    if ($s.state -ne 'down') {
        & $ctl down | Out-Null
        if (-not (WaitFor 20 { param($x) $x.state -eq 'down' })) { Fail 'could not take the tunnel down before the test' }
    }

    Write-Host '== 2. device key'
    $fingerprint = $s.fingerprint
    if ($s.key_kind -eq 'tpm2' -and $s.hardware_bound) {
        Pass "key in the TPM, hardware-bound, fingerprint $($s.fingerprint)"
    } elseif ($AllowSoftkey) {
        Write-Warning "key kind $($s.key_kind), hardware-bound $($s.hardware_bound) (accepted with -AllowSoftkey)"
    } else {
        Fail "key kind $($s.key_kind), hardware-bound $($s.hardware_bound): expected tpm2 (see docs/WINDOWS.md, TPM)"
    }

    Write-Host '== 3. approval'
    if ($s.enrollment -ne 'approved') {
        Write-Host "   enrollment is '$($s.enrollment)'. Run: boundgatectl enroll"
        Write-Host "   then confirm and sign in the admin UI (fingerprint $($s.fingerprint)) and run this again."
        Fail 'not approved'
    }
    $s = WaitFor 30 { param($x) $x.binding -eq 'verified' }
    if (-not $s) { Fail 'the node''s binding does not verify (boundgatectl identity)' }
    Pass 'approved, binding verified'

    Write-Host '== 4. up'
    $before = RouteTable
    $upArgs = @('up')
    if ($NodeProfile) { $upArgs += @('-profile', $NodeProfile) }
    & $ctl @upArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'boundgatectl up refused' }
    $s = WaitFor 30 { param($x) $x.state -eq 'up' -and ((Has $x 'login_required') -or ((Has $x 'hubs') -and @($x.hubs | Where-Object { $_.state -eq 'connected' }).Count -gt 0)) }
    if (-not $s) { Fail 'the tunnel did not come up within 30 s' }
    if ((Has $s 'login_required') -and $s.login_required) {
        Write-Host '   the hubs want a sign-in: a browser opens'
        $start = & $ctl -json login -no-wait | Out-String | ConvertFrom-Json
        Start-Process $start.url
        & $ctl login -timeout 5m
        if ($LASTEXITCODE -ne 0) { Fail 'sign-in failed' }
    }
    $s = WaitFor 30 { param($x) (Has $x 'hubs') -and @($x.hubs | Where-Object { $_.state -eq 'connected' }).Count -gt 0 }
    if (-not $s) { Fail 'no hub connected within 30 s' }
    $hub = @($s.hubs | Where-Object { $_.state -eq 'connected' })[0]
    Pass "connected to $($hub.name) over $($hub.transport), address $($s.overlay_ip), adapter $($s.interface) mtu $($s.mtu)"
    $adapter = Get-NetAdapter -Name $s.interface -ErrorAction SilentlyContinue
    if (-not $adapter) { Fail "adapter $($s.interface) not found" }
    $ip = Get-NetIPAddress -InterfaceAlias $s.interface -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $ip -or $ip.IPAddress -ne $s.overlay_ip) { Fail "adapter address $($ip.IPAddress), expected $($s.overlay_ip)" }
    $routes = @(Get-NetRoute -InterfaceAlias $s.interface -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    Pass "adapter up with $($routes.Count) routes"

    Write-Host "== 5. $Target`:$Port through the tunnel"
    # Find-NetRoute answers the source address and the route; keep the route
    $r = Find-NetRoute -RemoteIPAddress $Target -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } | Select-Object -First 1
    if ($r -and $r.InterfaceAlias -ne $s.interface) { Fail "$Target is routed over $($r.InterfaceAlias), not the tunnel (profile?)" }
    $t = Test-NetConnection -ComputerName $Target -Port $Port -WarningAction SilentlyContinue
    if (-not $t.TcpTestSucceeded) { Fail "$Target`:$Port does not answer (policy? boundgatectl flows)" }
    Pass "$Target`:$Port answers"
    $s = Status
    $hub = @($s.hubs | Where-Object { $_.state -eq 'connected' })[0]
    Pass "tunnel counters: in $($hub.bytes_in) B, out $($hub.bytes_out) B"

    Write-Host '== 6. down leaves nothing behind'
    $ifname = $s.interface
    & $ctl down | Out-Null
    if (-not (WaitFor 20 { param($x) $x.state -eq 'down' })) { Fail 'down did not finish' }
    Start-Sleep -Seconds 2
    if (Get-NetAdapter -Name $ifname -ErrorAction SilentlyContinue) { Fail "adapter $ifname is still there" }
    $after = RouteTable
    $diff = Compare-Object -ReferenceObject $before -DifferenceObject $after
    if ($diff) {
        $diff | ForEach-Object { Write-Host "   $($_.SideIndicator) $($_.InputObject)" }
        Fail 'the routing table differs from before up (<= missing now, => new)'
    }
    Pass 'adapter gone, routing table as before'

    Write-Host '== 7. service restart'
    $autoUp = (Get-Content (Join-Path $env:ProgramData 'BoundGate\node.yaml') -Raw) -match '(?m)^\s*auto_up:\s*true'
    Restart-Service -Name BoundGate
    $s = WaitFor 30 { param($x) $x.enrollment -eq 'approved' }
    if (-not $s) { Fail 'the service did not come back approved within 30 s' }
    if ($s.fingerprint -ne $fingerprint) { Fail "the identity changed across the restart: $($s.fingerprint), was $fingerprint" }
    Pass "back, same identity (fingerprint $($s.fingerprint))"
    if ($autoUp) {
        if (-not (WaitFor 45 { param($x) (Has $x 'hubs') -and @($x.hubs | Where-Object { $_.state -eq 'connected' }).Count -gt 0 })) { Fail 'auto_up: no hub connected within 45 s after the restart' }
        Pass 'auto_up: connected again by itself'
        & $ctl down | Out-Null
    } else {
        Write-Host '   (auto_up is off in node.yaml: the tunnel stays down after a restart, as configured)'
    }

    Write-Host ''
    Write-Host 'PASS' -ForegroundColor Green
    Write-Host 'Manual rest of M10: a policy with hardware_bound admits this node; a reboot with auto_up: true reconnects; uninstall.ps1 leaves no adapter.'
} catch {
    if (-not $script:failed) { Write-Host "FAIL: $_" -ForegroundColor Red }
    & $ctl down *> $null
    Stop-Transcript | Out-Null
    exit 1
}
Stop-Transcript | Out-Null
