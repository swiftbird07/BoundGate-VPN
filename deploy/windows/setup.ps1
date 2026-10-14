<#
  Installs or updates BoundGate on Windows from the latest release, in one line
  (PowerShell as administrator):

    irm https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/windows/setup.ps1 | iex

  or, to read it first:

    irm https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/windows/setup.ps1 -OutFile setup.ps1
    notepad setup.ps1; powershell -ExecutionPolicy Bypass -File .\setup.ps1

  The Windows counterpart of deploy/prod/setup.sh, for a device rather than a
  server: it finds the latest release on GitHub, checks its manifest.json
  against the release keys (ssh-keygen -Y verify, as update.sh does), checks the
  zip for this machine against the manifest (size and SHA-256), downloads
  wintun-0.14.1.zip from www.wintun.net if Wintun is not installed yet (whose
  hash and signature install.ps1 checks), and runs the release's install.ps1.
  The tray then asks for the control plane, unless BOUNDGATE_CONTROL names it.

  Settings, as environment variables (iex takes no parameters):
    BOUNDGATE_CONTROL   control plane address, passed to install.ps1 -Control
    BOUNDGATE_REF       a release tag instead of the latest one
    BOUNDGATE_REPO      owner/name on GitHub (default swiftbird07/BoundGate-VPN)

  Trust: the release keys come from the same place as this script (GitHub, at
  the release's tag), like setup.sh's kit: the signature guards against a
  swapped release file, not against whoever controls the repository (R99).
#>
# one script block: under iex, nothing of this stays behind in the session
& {
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
# Windows PowerShell 5.1 may not offer TLS 1.2 by itself, and its progress bar
# makes Invoke-WebRequest many times slower
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

function Stop-Setup([string]$Why) { throw "setup: $Why" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Setup 'run this in PowerShell as administrator.'
}

$repo = if ($env:BOUNDGATE_REPO) { $env:BOUNDGATE_REPO } else { 'swiftbird07/BoundGate-VPN' }
if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { Stop-Setup "BOUNDGATE_REPO must be owner/name, got $repo" }
# a 32-bit PowerShell on a 64-bit Windows sees x86 here; the machine's own is in the W6432 variable
$machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($machine) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { Stop-Setup "unsupported architecture $machine" } }
$installDir = Join-Path $env:ProgramFiles 'BoundGate'

$sshKeygen = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
if (-not $sshKeygen) {
    Stop-Setup ('ssh-keygen is needed to check the release signature. Add the OpenSSH client: ' +
        'Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0')
}

# --- which release
$vpat = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
$tag = $env:BOUNDGATE_REF
if (-not $tag) {
    try { $tag = (Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 "https://api.github.com/repos/$repo/releases/latest").tag_name }
    catch { Stop-Setup "cannot read the latest release of $repo ($($_.Exception.Message))" }
}
if ($tag -notmatch $vpat) { Stop-Setup "the release is not a version: $tag" }
Write-Host "BoundGate setup ($tag, windows/$arch)"

$work = Join-Path $env:TEMP ('boundgate-setup-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    function Get-File([string]$Url, [string]$Name) {
        $out = Join-Path $work $Name
        try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 600 -Uri $Url -OutFile $out }
        catch { Stop-Setup "cannot download $Url ($($_.Exception.Message))" }
        $out
    }
    $dl = "https://github.com/$repo/releases/download/$tag"
    $manifest = Get-File "$dl/manifest.json" 'manifest.json'
    $sig = Get-File "$dl/manifest.json.sig" 'manifest.json.sig'
    $keys = Get-File "https://raw.githubusercontent.com/$repo/$tag/deploy/prod/release_keys" 'release_keys'

    # --- the one place where trust comes from (as in update.sh)
    $allowed = @(Get-Content -LiteralPath $keys | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' } |
        ForEach-Object { 'boundgate-release ' + $_.Trim() })
    if ($allowed.Count -eq 0) { Stop-Setup "the release keys of $tag name no key" }
    $allowedFile = Join-Path $work 'allowed'
    # LF and no byte order mark: ssh-keygen reads it as OpenSSH writes it
    [IO.File]::WriteAllText($allowedFile, (($allowed -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
    # the manifest goes in as bytes: a PowerShell pipe would re-encode it
    $q = { param($p) '"' + $p + '"' }
    $verify = Start-Process -FilePath $sshKeygen.Path -NoNewWindow -Wait -PassThru `
        -ArgumentList @('-Y', 'verify', '-f', (& $q $allowedFile), '-I', 'boundgate-release', '-n', 'boundgate-release', '-s', (& $q $sig)) `
        -RedirectStandardInput $manifest -RedirectStandardOutput (Join-Path $work 'verify.out') -RedirectStandardError (Join-Path $work 'verify.err')
    if ($verify.ExitCode -ne 0) {
        Stop-Setup "the manifest of $tag is not signed by a release key: refusing ($((Get-Content -Raw (Join-Path $work 'verify.err')).Trim()))"
    }
    $m = [IO.File]::ReadAllText($manifest) | ConvertFrom-Json
    if ($m.type -ne 'boundgate-release' -or $m.version -cne $tag) { Stop-Setup "release $tag carries the signed manifest of $($m.version): refusing" }
    $asset = @($m.assets | Where-Object { $_.kind -eq 'binaries' -and $_.os -eq 'windows' -and $_.arch -eq $arch })
    if ($asset.Count -ne 1) { Stop-Setup "release $tag has no Windows build for $arch" }
    $asset = $asset[0]
    if ($asset.name -notmatch '^[A-Za-z0-9._-]+\.zip$') { Stop-Setup "bad asset name $($asset.name)" }
    Write-Host "   manifest signed by a release key"

    # --- the zip, as the signed manifest says
    $zip = Get-File "$dl/$($asset.name)" $asset.name
    $size = (Get-Item -LiteralPath $zip).Length
    $sum = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    if ($size -ne [long]$asset.size -or $sum -cne $asset.sha256) {
        Stop-Setup "$($asset.name) does not match the signed manifest: refusing"
    }
    Write-Host "   $($asset.name) matches it (SHA-256 $sum)"
    $unpacked = Join-Path $work 'x'
    Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
    $install = Get-ChildItem -LiteralPath $unpacked -Recurse -Filter install.ps1 | Select-Object -First 1
    if (-not $install) { Stop-Setup "$($asset.name) has no install.ps1" }

    # --- Wintun, once: install.ps1 checks the zip's hash and the DLL's signature
    $installArgs = @{}
    if (-not (Test-Path -LiteralPath (Join-Path $installDir 'wintun.dll'))) {
        $installArgs.WintunZip = Get-File 'https://www.wintun.net/builds/wintun-0.14.1.zip' 'wintun-0.14.1.zip'
    }
    if ($env:BOUNDGATE_CONTROL) { $installArgs.Control = $env:BOUNDGATE_CONTROL }

    # install.ps1 is a file; a machine's default policy runs none. This process only
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    & $install.FullName @installArgs
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
}
