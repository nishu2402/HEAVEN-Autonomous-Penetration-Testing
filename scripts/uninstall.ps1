#Requires -Version 5.1
<#
==============================================================================
  HEAVEN - Autonomous Penetration Testing Framework
  Windows uninstaller (PowerShell) v1.0.0

  Removes: the venv, the user-PATH entry, egg-info and __pycache__.
  Keeps:   source code, and any non-empty scan / engagement / report data.
  Never touches the external scanner tools (nmap, docker, ...) - those are
  shared system software you may use elsewhere.

  Run from the repo root:
      powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1
==============================================================================
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'   # run every cleanup step even if one fails

function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }

$InstallDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "              HEAVEN Uninstaller (Windows) v1.0.0            " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "Project directory: $InstallDir"
Write-Host ""

$VenvDir     = Join-Path $InstallDir 'venv'
$VenvScripts = Join-Path $VenvDir 'Scripts'

# -- Step 1: Remove venv\Scripts from the user PATH ---------------------------
Write-Info "Step 1/4 - Removing PATH entry..."
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not [string]::IsNullOrEmpty($userPath)) {
    $parts = $userPath.Split(';') | Where-Object { $_ -ne '' -and $_ -ne $VenvScripts }
    $newPath = ($parts -join ';')
    if ($newPath -ne $userPath) {
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Ok "Removed $VenvScripts from user PATH"
    } else {
        Write-Warn "No HEAVEN PATH entry found (already removed or never installed)"
    }
} else {
    Write-Warn "User PATH is empty - nothing to remove"
}

# -- Step 2: Remove the virtual environment -----------------------------------
Write-Info "Step 2/4 - Removing virtual environment..."
if (Test-Path $VenvDir) {
    Remove-Item -Recurse -Force $VenvDir -ErrorAction SilentlyContinue
    if (-not (Test-Path $VenvDir)) { Write-Ok "Removed: $VenvDir" }
    else { Write-Warn "Could not fully remove $VenvDir (a process may be using it)" }
} else {
    Write-Warn "venv not found (already removed)"
}

# -- Step 3: Remove Python build artifacts ------------------------------------
Write-Info "Step 3/4 - Removing Python build artifacts..."
foreach ($egg in @('heaven.egg-info', 'heaven_pentest.egg-info')) {
    $p = Join-Path $InstallDir $egg
    if (Test-Path $p) { Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue; Write-Ok "Removed: $egg" }
}
$cacheCount = 0
Get-ChildItem -Path $InstallDir -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(\.git|venv)\\' } |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue; $cacheCount++ }
if ($cacheCount -gt 0) { Write-Ok "Removed $cacheCount __pycache__ dir(s)" }
Write-Ok "Build artifacts cleaned"

# -- Step 4: Report on runtime data -------------------------------------------
Write-Info "Step 4/4 - Checking runtime data directories..."
$hasData = $false
foreach ($rel in @('data\scans', 'data\reports', 'data\cache', 'data\audit', 'data\engagements', 'engagements')) {
    $dir = Join-Path $InstallDir $rel
    if (-not (Test-Path $dir)) { continue }
    $items = Get-ChildItem -Force $dir -ErrorAction SilentlyContinue
    if (-not $items) {
        Remove-Item -Force $dir -ErrorAction SilentlyContinue
        Write-Ok "Removed empty: $dir"
    } else {
        Write-Warn "Keeping non-empty: $dir  (delete manually if you want it gone)"
        $hasData = $true
    }
}
if (-not $hasData) { Write-Ok "No residual scan data found" }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "              HEAVEN uninstalled successfully               " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Source code kept at: $InstallDir"
Write-Host "  To delete entirely:  Remove-Item -Recurse -Force `"$InstallDir`""
Write-Host ""
Write-Warn "Open a NEW terminal so the PATH change takes effect."
Write-Host ""
