<#
.SYNOPSIS
    Installs ghsec on Windows.

.DESCRIPTION
    Downloads the release archive for this machine's architecture, verifies its
    SHA-256 against the published SHA256SUMS file, and installs ghsec.exe into a
    user-owned directory. It never requires administrator rights and never
    changes machine-wide settings.

.EXAMPLE
    irm https://raw.githubusercontent.com/yuuuuukiu/ghsec/main/install.ps1 | iex

.EXAMPLE
    # install a specific version into a custom directory
    $env:GHSEC_VERSION = 'v1.0.0'
    $env:GHSEC_INSTALL_DIR = 'C:\tools\ghsec'
    .\install.ps1

.NOTES
    Environment variables:
      GHSEC_VERSION      tag to install (default: the latest release)
      GHSEC_INSTALL_DIR  target directory (default: %LOCALAPPDATA%\ghsec\bin)
      GHSEC_NO_VERIFY    set to 1 to skip checksum verification
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Repo = 'yuuuuukiu/ghsec'
$Bin = 'ghsec.exe'

# Windows PowerShell 5.1 defaults to older TLS versions, which GitHub rejects.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    # Newer PowerShell versions negotiate this automatically.
}

function Write-Step($Message) { Write-Host "  $Message" }
function Stop-Install($Message) { Write-Error $Message; exit 1 }

# --- platform detection -----------------------------------------------------

$Architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    # A 32-bit PowerShell on 64-bit Windows reports x86 here; use the real one.
    'x86' {
        if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { 'amd64' } else { Stop-Install 'ghsec does not ship a 32-bit Windows build' }
    }
    default { Stop-Install "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}

# --- version resolution -----------------------------------------------------

$Version = $env:GHSEC_VERSION
if ([string]::IsNullOrWhiteSpace($Version)) {
    Write-Step 'resolving the latest ghsec release...'
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        $Version = $release.tag_name
    } catch {
        Stop-Install "could not determine the latest release. Set `$env:GHSEC_VERSION and retry. ($($_.Exception.Message))"
    }
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    Stop-Install 'the latest release did not report a tag name; set $env:GHSEC_VERSION explicitly'
}

$Num = $Version -replace '^v', ''
$Asset = "ghsec_${Num}_windows_${Architecture}.zip"
$Base = "https://github.com/$Repo/releases/download/$Version"

Write-Host "installing ghsec $Version for windows/$Architecture"

$Temp = Join-Path ([IO.Path]::GetTempPath()) ("ghsec-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp -Force | Out-Null

try {
    $ArchivePath = Join-Path $Temp $Asset
    $SumsPath = Join-Path $Temp 'SHA256SUMS'

    Write-Step "downloading $Asset"
    try {
        Invoke-WebRequest -Uri "$Base/$Asset" -OutFile $ArchivePath -UseBasicParsing
    } catch {
        Stop-Install "download failed: $Base/$Asset`nCheck that release $Version publishes a windows/$Architecture build."
    }

    Write-Step 'downloading SHA256SUMS'
    try {
        Invoke-WebRequest -Uri "$Base/SHA256SUMS" -OutFile $SumsPath -UseBasicParsing
    } catch {
        Stop-Install "could not download SHA256SUMS for $Version"
    }

    # --- checksum verification ---------------------------------------------
    if ($env:GHSEC_NO_VERIFY -eq '1') {
        Write-Step 'skipping checksum verification (GHSEC_NO_VERIFY=1)'
    } else {
        $expected = (Get-Content $SumsPath | Where-Object { $_ -match "\s$([Regex]::Escape($Asset))$" } | Select-Object -First 1)
        if (-not $expected) { Stop-Install "no checksum published for $Asset; refusing to install" }
        $expectedHash = ($expected -split '\s+')[0].ToLowerInvariant()
        $actualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expectedHash -ne $actualHash) {
            Stop-Install "checksum mismatch for ${Asset}:`n  expected: $expectedHash`n  actual:   $actualHash`nThe download may be corrupted or tampered with. Aborting."
        }
        Write-Step 'checksum verified'
    }

    # --- extract and install ------------------------------------------------
    Write-Step 'extracting'
    Expand-Archive -Path $ArchivePath -DestinationPath $Temp -Force

    $Extracted = Join-Path $Temp $Bin
    if (-not (Test-Path $Extracted)) { Stop-Install "the archive did not contain $Bin" }

    $InstallDir = $env:GHSEC_INSTALL_DIR
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'ghsec\bin'
    }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    $Destination = Join-Path $InstallDir $Bin
    if (Test-Path $Destination) { Write-Step "replacing existing $Destination" }
    Copy-Item -Path $Extracted -Destination $Destination -Force

    Write-Host ''
    Write-Host "ghsec $Version installed to $Destination"

    # --- PATH guidance ------------------------------------------------------
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $onPath = ($userPath -split ';') -contains $InstallDir
    if (-not $onPath) {
        Write-Host ''
        Write-Host "note: $InstallDir is not on your user PATH."
        Write-Host 'To add it for the current user, run:'
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"$InstallDir;`$env:Path`", 'User')"
        Write-Host 'then open a new terminal.'
    }

    Write-Host ''
    Write-Host "run 'ghsec' to start the interactive UI, or 'ghsec --help' for the CLI."
} finally {
    Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
}
