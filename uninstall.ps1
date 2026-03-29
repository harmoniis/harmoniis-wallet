# uninstall.ps1 - Harmoniis Wallet uninstaller for Windows
#
# Removes the hrmw binary and PATH entry.
# DOES NOT touch wallet data at ~/.harmoniis/ - your keys and funds are safe.

$ErrorActionPreference = "Stop"

function Write-Section([string]$Message, [string]$Color = "Cyan") {
    Write-Host "  $Message" -ForegroundColor $Color
}

function Write-Ok([string]$Message) {
    Write-Section "[ok] $Message" "Green"
}

function Write-Warn([string]$Message) {
    Write-Section "[!!] $Message" "Yellow"
}

function Get-BinDir {
    if ($env:HRMW_BIN_DIR) {
        return $env:HRMW_BIN_DIR
    }
    $localRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else {
        Join-Path $env:USERPROFILE "AppData\Local"
    }
    return Join-Path $localRoot "Harmoniis\bin"
}

# # Main

Write-Host ""
Write-Section "Harmoniis Wallet (hrmw) - uninstaller for Windows"
Write-Host ""

$binDir = Get-BinDir
$binPath = Join-Path $binDir "hrmw.exe"

if (Test-Path $binPath) {
    Write-Section "[->] Removing $binPath" "Yellow"
    Remove-Item $binPath -Force
    # Also clean up .old.exe from self-update if present.
    $oldPath = Join-Path $binDir "hrmw.old.exe"
    if (Test-Path $oldPath) { Remove-Item $oldPath -Force }
    Write-Ok "Binary removed"
} else {
    Write-Warn "Binary not found at $binPath - already uninstalled?"
}

# Remove empty bin directory.
if ((Test-Path $binDir) -and ((Get-ChildItem $binDir -Force | Measure-Object).Count -eq 0)) {
    Remove-Item $binDir -Force
}

# Remove from user PATH.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -and $userPath.Contains($binDir)) {
    $entries = $userPath.Split(';') | Where-Object { $_ -and $_ -ne $binDir }
    $newPath = $entries -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Ok "Removed $binDir from user PATH"
}

Write-Host ""
Write-Ok "hrmw has been uninstalled."
Write-Host ""
Write-Host "  Your wallet data at ~/.harmoniis/ has NOT been touched."
Write-Host "  Your keys and funds are safe."
Write-Host ""
Write-Host "  To remove wallet data permanently (IRREVERSIBLE):"
Write-Host "    Remove-Item -Recurse -Force `"$env:USERPROFILE\.harmoniis`""
Write-Host ""
