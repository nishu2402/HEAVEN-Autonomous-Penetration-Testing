#Requires -Version 5.1
<#
==============================================================================
  HEAVEN - Autonomous Penetration Testing Framework
  Windows uninstaller (PowerShell) v3.1.0

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

# Windows uninstaller — refuse to run on macOS / Linux (PowerShell 7+ is cross-platform),
# where it would delete the Unix venv/ and can't touch the user PATH anyway. Use the shell
# script. (On Windows PowerShell 5.1 $IsWindows is undefined and Major is 5, so this never
# fires there.)
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    Write-Host "[x] This is the Windows uninstaller. On macOS / Linux run:  ./scripts/uninstall.sh" -ForegroundColor Red
    exit 1
}

function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }

$InstallDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "              HEAVEN Uninstaller (Windows) v3.1.0            " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "Project directory: $InstallDir"
Write-Host ""

$VenvDir     = Join-Path $InstallDir 'venv'
$VenvScripts = Join-Path $VenvDir 'Scripts'

# -- Step 1: Remove venv\Scripts from the user PATH + Tab-completion -----------
Write-Info "Step 1/4 - Removing PATH entry + Tab-completion..."
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

# Strip the Tab-completion block from $PROFILE and delete the completion script.
# Done directly (not via `heaven completion --uninstall`) because the venv is
# removed in Step 2 — the command may already be gone.
$profilePath = $PROFILE.CurrentUserAllHosts
if ($profilePath -and (Test-Path $profilePath)) {
    $text = Get-Content -Raw -Path $profilePath
    if ($text -match '# >>> heaven completion >>>') {
        $pattern = '(?ms)^# >>> heaven completion >>>.*?^# <<< heaven completion <<<\r?\n?'
        $new = [regex]::Replace($text, $pattern, '')
        Set-Content -Path $profilePath -Value $new -NoNewline
        Remove-Item -Force "$profilePath.heaven.bak" -ErrorAction SilentlyContinue
        Write-Ok "Removed Tab-completion block from $profilePath"
    }
}
$compPs1 = Join-Path $HOME '.config\heaven\completion.ps1'
if (Test-Path $compPs1) {
    Remove-Item -Force $compPs1 -ErrorAction SilentlyContinue
    Write-Ok "Removed: $compPs1"
    # Prune the completion dir if now empty.
    $compDir = Split-Path $compPs1 -Parent
    if ((Test-Path $compDir) -and -not (Get-ChildItem -Force $compDir -ErrorAction SilentlyContinue)) {
        Remove-Item -Force $compDir -ErrorAction SilentlyContinue
    }
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

# Cleanup uses only cmdlets, so no native command ever sets $LASTEXITCODE; a
# caller that checks `if ($LASTEXITCODE -ne 0)` would otherwise read the fresh
# session's $null and treat a clean uninstall as a failure. Exit explicitly.
exit 0
