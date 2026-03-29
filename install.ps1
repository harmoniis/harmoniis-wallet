# install.ps1 - Harmoniis Wallet installer for Windows
#
# Usage:
#   irm https://harmoniis.com/wallet/install.ps1 | iex
#   irm https://github.com/harmoniis/harmoniis-wallet/releases/latest/download/install.ps1 | iex
#
# Environment variables:
#   HRMW_VERSION   - pin to a specific version (default: latest)
#   HRMW_BIN_DIR   - override install directory (default: LOCALAPPDATA\Harmoniis\bin)

$ErrorActionPreference = "Stop"

function Write-Section([string]$Message, [string]$Color = "Cyan") {
    Write-Host "  $Message" -ForegroundColor $Color
}

function Write-Step([string]$Message) {
    Write-Section "[->] $Message" "Yellow"
}

function Write-Ok([string]$Message) {
    Write-Section "[ok] $Message" "Green"
}

function Write-Warn([string]$Message) {
    Write-Section "[!!] $Message" "Yellow"
}

function Get-LocalAppDataRoot {
    if ($env:LOCALAPPDATA) {
        return $env:LOCALAPPDATA
    }
    return Join-Path $env:USERPROFILE "AppData\Local"
}

function Get-BinDir {
    if ($env:HRMW_BIN_DIR) {
        return $env:HRMW_BIN_DIR
    }
    $localRoot = Get-LocalAppDataRoot
    return Join-Path $localRoot "Harmoniis\bin"
}

function Ensure-Dir([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Add-UserPathEntry([string]$BinDir) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @()
    if ($userPath) {
        $entries = $userPath.Split(';') | Where-Object { $_ }
    }
    $changed = $false
    if ($entries -notcontains $BinDir) {
        $newUserPath = if ($userPath -and $userPath.Trim().Length -gt 0) {
            "$userPath;$BinDir"
        } else {
            $BinDir
        }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        $changed = $true
    }
    # Update the current session so hrmw works immediately.
    $sessionEntries = $env:Path.Split(';') | Where-Object { $_ }
    if ($sessionEntries -notcontains $BinDir) {
        $env:Path = "$BinDir;$env:Path"
    }
    # Broadcast WM_SETTINGCHANGE so other open shells pick up the change.
    if ($changed) {
        try {
            if (-not ('Win32.NativeMethods' -as [type])) {
                Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
            }
            $HWND_BROADCAST = [IntPtr]0xffff
            $WM_SETTINGCHANGE = 0x1a
            $result = [UIntPtr]::Zero
            [Win32.NativeMethods]::SendMessageTimeout(
                $HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero,
                "Environment", 2, 5000, [ref]$result
            ) | Out-Null
        } catch { }
    }
}

function Get-LatestReleaseVersion {
    $repo = "harmoniis/harmoniis-wallet"
    $apiUrl = "https://api.github.com/repos/$repo/releases/latest"
    $release = Invoke-RestMethod -Uri $apiUrl
    return $release.tag_name -replace '^v', ''
}

function Download-ReleaseArtifact([string]$Version) {
    $repo = "https://github.com/harmoniis/harmoniis-wallet"
    $tmpRoot = Join-Path $env:TEMP ("hrmw-install-" + [guid]::NewGuid().ToString("N"))
    Ensure-Dir $tmpRoot

    $tarball = "harmoniis-wallet-$Version-windows-x86_64.tar.gz"
    $tarballPath = Join-Path $tmpRoot $tarball
    $url = "$repo/releases/download/v$Version/$tarball"
    Write-Step "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $tarballPath

    # SHA256 verification
    $checksumPath = "$tarballPath.sha256"
    try {
        Invoke-WebRequest -Uri "$url.sha256" -OutFile $checksumPath | Out-Null
        $expected = ((Get-Content $checksumPath | Select-Object -First 1) -split '\s+')[0].Trim()
        $actual = (Get-FileHash -Algorithm SHA256 $tarballPath).Hash.ToLowerInvariant()
        if ($expected.ToLowerInvariant() -ne $actual) {
            throw "checksum mismatch for $tarball (expected $expected, got $actual)"
        }
        Write-Ok "SHA256 verified"
    } catch {
        Write-Warn "Checksum verification skipped: $($_.Exception.Message)"
    }

    Write-Step "Extracting $tarball"
    # Use Windows native tar.exe explicitly to avoid MSYS2/Git Bash tar
    # intercepting and choking on Windows paths.
    $tarExe = Join-Path $env:SystemRoot "System32\tar.exe"
    if (-not (Test-Path $tarExe)) { $tarExe = "tar" }
    & $tarExe -xzf $tarballPath -C $tmpRoot
    $artifactRoot = Get-ChildItem $tmpRoot -Directory | Where-Object { $_.Name -like "harmoniis-wallet-*" } | Select-Object -First 1
    if (-not $artifactRoot) {
        throw "extraction failed - no harmoniis-wallet-* directory found in tarball"
    }
    return @{
        TempRoot = $tmpRoot
        ArtifactRoot = $artifactRoot.FullName
    }
}

# # Main

Write-Host ""
Write-Section "Harmoniis Wallet (hrmw) - installer for Windows"
Write-Host ""

$version = if ($env:HRMW_VERSION) { $env:HRMW_VERSION } else { Get-LatestReleaseVersion }
$binDir = Get-BinDir

Write-Step "Installing hrmw v$version"
Write-Host "    target: $binDir\hrmw.exe"

$download = Download-ReleaseArtifact $version
try {
    $binSource = Join-Path $download.ArtifactRoot "bin\hrmw.exe"
    if (-not (Test-Path $binSource)) {
        throw "hrmw.exe not found in release archive at $binSource"
    }

    Ensure-Dir $binDir
    Copy-Item $binSource (Join-Path $binDir "hrmw.exe") -Force

    Add-UserPathEntry $binDir

    $versionText = & (Join-Path $binDir "hrmw.exe") --version 2>$null
    Write-Ok "Installed: $versionText"
    Write-Host "    binary: $(Join-Path $binDir 'hrmw.exe')"
    Write-Host ""
    Write-Host "  Next steps:"
    Write-Host "    hrmw setup"
    Write-Host "    hrmw webminer bench"
    Write-Host "    hrmw upgrade              (future updates)"
    Write-Host ""
} finally {
    Remove-Item $download.TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
