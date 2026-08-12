#Requires -Version 5.1
<#
==============================================================================
  HEAVEN - Autonomous Penetration Testing Framework
  Windows installer (PowerShell) v2.1.0

  ONE command sets up everything, the same as scripts/install.sh does on
  macOS / Linux:
    - a Python virtual environment
    - HEAVEN + every runtime dependency (full power by default)
    - the external scanner tools (nmap / nuclei / sqlmap / ffuf / semgrep /
      docker) via winget / choco / scoop / pip / go
    - the web UI (if Node.js is present)
    - PowerShell Tab-completion for the 'heaven' command
    - a ready-to-use .env with generated credentials

  Run from the repo root (an ordinary, non-admin PowerShell is fine):

      powershell -ExecutionPolicy Bypass -File scripts\install.ps1

  Options:
      -CoreOnly    skip the optional feature packs (leanest install)
      -SkipTools   don't install the external scanner tools
      -SkipUI      don't build the web UI
==============================================================================
#>

[CmdletBinding()]
param(
    [switch]$CoreOnly,
    [switch]$SkipTools,
    [switch]$SkipUI
)

$ErrorActionPreference = 'Stop'

# This is the WINDOWS installer. PowerShell 7+ is cross-platform, so a stray run on
# macOS / Linux would look for a Windows venv layout (venv\Scripts\), reach for
# winget/choco/scoop and cmd.exe, and otherwise misbehave. Stop early and point to the
# shell installer. (On Windows PowerShell 5.1 $IsWindows is undefined and Major is 5, so
# this never fires there; it only guards the cross-platform pwsh 7+ case.)
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    Write-Host "[x] This is the Windows installer. On macOS / Linux run:  ./scripts/install.sh" -ForegroundColor Red
    exit 1
}

# Keep the $LASTEXITCODE-based flow below authoritative on every PowerShell edition.
# PowerShell 7.4+ makes a native command's non-zero exit throw a terminating error under
# ErrorActionPreference 'Stop', which would turn the intentionally non-fatal steps
# (optional feature packs, external tools) into hard aborts before their own
# $LASTEXITCODE check runs. Opting out makes Windows PowerShell 5.1 and pwsh 7 behave
# identically (harmless no-op on 5.1, which lacks this preference variable).
$PSNativeCommandUseErrorActionPreference = $false

# -- Pretty output ------------------------------------------------------------
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Step { param($m) Write-Host "[>] $m" -ForegroundColor Cyan }
function Die        { param($m) Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   H E A V E N  -  Autonomous Penetration Testing Framework " -ForegroundColor Cyan
Write-Host "   Windows installer" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Repo root - this script lives in scripts\, so resolve one level up.
$InstallDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Info "Install directory: $InstallDir"

# Honour the same env-var opt-outs as install.sh, so docs/CI stay consistent.
if ($env:HEAVEN_CORE_ONLY -eq '1')  { $CoreOnly = $true }
if ($env:HEAVEN_SKIP_TOOLS -eq '1') { $SkipTools = $true }

# -- 1. Python ----------------------------------------------------------------
Write-Step "Step 1/9 - Checking Python..."

# Prefer a stable, well-tested interpreter. HEAVEN's native security deps
# (asyncssh<->Nettle, cryptography, numpy/scikit-learn) are only ABI-stable on
# released Python lines; a brand-new major (e.g. 3.14 in its first months) can
# crash those C extensions. Ask the 'py' launcher for the newest known-good line
# (3.13 -> 3.12 -> 3.11) first, then fall back to whatever python is on PATH.
$PyExe = $null
$candidates = @(
    @{ cmd = 'py';      pre = @('-3.13') },
    @{ cmd = 'py';      pre = @('-3.12') },
    @{ cmd = 'py';      pre = @('-3.11') },
    @{ cmd = 'py';      pre = @('-3') },
    @{ cmd = 'python';  pre = @() },
    @{ cmd = 'python3'; pre = @() })
foreach ($cand in $candidates) {
    if (Get-Command $cand.cmd -ErrorAction SilentlyContinue) {
        # For versioned 'py' launches, confirm that exact version is installed.
        $probe = & $cand.cmd @($cand.pre) -c "print(1)" 2>$null
        if ($probe -and $probe.Trim() -eq '1') {
            $PyExe = $cand.cmd
            $PyPre = $cand.pre
            break
        }
    }
}
if (-not $PyExe) {
    Die "Python 3 is not installed. Get it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and re-run."
}

$verOk = & $PyExe @PyPre -c "import sys; print(1 if sys.version_info >= (3,11) else 0)"
$verStr = & $PyExe @PyPre -c "import sys; print('%d.%d.%d' % sys.version_info[:3])"
# 1 when newer than the newest line we test (3.13): usable, not yet vetted.
$verNew = & $PyExe @PyPre -c "import sys; print(1 if sys.version_info >= (3,14) else 0)"
if ($verOk.Trim() -ne '1') {
    Die "Python 3.11+ required. Found: $verStr. Please upgrade Python."
}
if ($verNew.Trim() -eq '1') {
    Write-Warn "Python $verStr is newer than HEAVEN's tested range (3.11-3.13)."
    Write-Warn "It should work, but native security libraries may not be ABI-stable"
    Write-Warn "on it yet. If you hit a native crash, install Python 3.12 or 3.13"
    Write-Warn "and re-run this installer (delete '$InstallDir\venv' first)."
}
Write-Ok "Python $verStr"

# -- 2. Virtual environment ---------------------------------------------------
Write-Step "Step 2/9 - Setting up virtual environment..."

$VenvDir    = Join-Path $InstallDir 'venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$VenvScripts = Join-Path $VenvDir 'Scripts'

if (-not (Test-Path $VenvPython)) {
    & $PyExe @PyPre -m venv $VenvDir
    if (-not (Test-Path $VenvPython)) { Die "Failed to create venv at $VenvDir" }
    Write-Ok "Created venv at $VenvDir"
} else {
    Write-Ok "Reusing existing venv at $VenvDir"
}

# -- 3. Pip toolchain ---------------------------------------------------------
Write-Step "Step 3/9 - Upgrading pip toolchain..."
& $VenvPython -m pip install --upgrade pip setuptools wheel -q
Write-Ok "pip / setuptools / wheel up to date"

# -- 4. Install HEAVEN --------------------------------------------------------
Write-Step "Step 4/9 - Installing HEAVEN..."
& $VenvPython -m pip install -e $InstallDir -q
if ($LASTEXITCODE -ne 0) { Die "Core install failed - see errors above." }
Write-Ok "HEAVEN core installed (editable mode)"

if ($CoreOnly) {
    Write-Info "Core-only requested - skipping optional feature packs"
} else {
    Write-Info "Installing optional feature packs (failures here are non-fatal)..."
    foreach ($extra in @('recon', 'reports', 'scheduling', 'lateral', 'deploy')) {
        & $VenvPython -m pip install -e "$InstallDir[$extra]" -q 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Ok "  + $extra" }
        else { Write-Warn "  - $extra skipped  (add later: pip install -e `".[$extra]`")" }
    }
}

# The playwright wheel ships in the core install; the Chromium bundle it drives
# (DOM/stored-XSS execution proof + JS-rendered crawl) is a separate ~150 MB
# download. Fetch it here so full power is on by default - same as install.sh.
# Non-fatal; skipped for a lean footprint (CoreOnly / HEAVEN_SKIP_BROWSER=1).
if ($CoreOnly -or $env:HEAVEN_SKIP_BROWSER -eq '1') {
    Write-Info "Skipping Playwright browser download (lean footprint)"
} else {
    & $VenvPython -m playwright install chromium 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Playwright Chromium installed (headless DAST proof enabled)"
    } else {
        Write-Warn "Playwright browser skipped  (enable later: python -m playwright install chromium)"
    }
}

# -- 5. Put 'heaven' on PATH --------------------------------------------------
Write-Step "Step 5/9 - Installing global 'heaven' command..."

$VenvHeaven = Join-Path $VenvScripts 'heaven.exe'
if (-not (Test-Path $VenvHeaven)) {
    Die "venv\Scripts\heaven.exe not found - did step 4 succeed? Check errors above."
}

# Persist venv\Scripts on the USER Path (no admin needed) so new terminals see
# `heaven`, and update the current session too. Idempotent.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ([string]::IsNullOrEmpty($userPath)) { $userPath = '' }
if ($userPath.Split(';') -notcontains $VenvScripts) {
    $newPath = if ($userPath.TrimEnd(';') -eq '') { $VenvScripts } else { "$($userPath.TrimEnd(';'));$VenvScripts" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Ok "Added $VenvScripts to your user PATH"
} else {
    Write-Ok "$VenvScripts already on user PATH"
}
$procPath = $env:Path
if ([string]::IsNullOrEmpty($procPath)) { $procPath = '' }
if ($procPath.Split(';') -notcontains $VenvScripts) {
    $env:Path = if ($procPath -eq '') { $VenvScripts } else { "$procPath;$VenvScripts" }
}
Write-Ok "heaven command: $VenvHeaven"

# -- Tab-completion (press <Tab> to complete commands, options and values) -----
# Click ships no PowerShell completion backend, so HEAVEN provides a native
# argument-completer that `heaven completion --install powershell` wires into
# your $PROFILE (idempotent, backed up first). This is the "Tab does nothing"
# pain point, handled at install time. Best-effort - never aborts the install.
# Opt out with HEAVEN_SKIP_COMPLETION=1.
if ($env:HEAVEN_SKIP_COMPLETION -eq '1') {
    Write-Info "HEAVEN_SKIP_COMPLETION=1 - skipping Tab-completion (enable later: heaven completion --install)"
} else {
    Write-Info "Enabling PowerShell Tab-completion (commands, options and values)..."
    & $VenvPython -m heaven.main --quiet completion --install powershell 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Tab-completion installed - open a new terminal (or run: . `$PROFILE), then press Tab after 'heaven '"
    } else {
        Write-Warn "Tab-completion setup skipped (enable later: heaven completion --install)"
    }
}

# -- 6. External tools --------------------------------------------------------
Write-Step "Step 6/9 - Installing external scanner tools..."

if ($SkipTools) {
    Write-Info "Skipping external tool install (run later with: heaven install-tools)"
} else {
    Write-Info "Installing nmap / nuclei / sqlmap / ffuf / semgrep / docker via winget / choco / scoop / pip / go"
    Write-Info "This downloads real binaries and can take a few minutes - progress prints below."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue) -and
        -not (Get-Command choco  -ErrorAction SilentlyContinue) -and
        -not (Get-Command scoop  -ErrorAction SilentlyContinue)) {
        Write-Warn "No Windows package manager (winget/choco/scoop) found - only pip/go-installable tools will land."
        Write-Warn "winget ships with Windows 10/11; or install Scoop from https://scoop.sh for the rest."
    }
    & $VenvPython -m heaven.main --quiet install-tools --yes
    if ($LASTEXITCODE -eq 0) { Write-Ok "External tools ready (or already present)" }
    else {
        Write-Warn "Some external tools couldn't be installed automatically (non-fatal - each has a fallback)"
        Write-Host "    Re-run any time:  heaven install-tools   -   see what's missing:  heaven doctor"
    }
}

# -- Optional: local AI (Ollama) - no API key, no rate limits ------------------
# OPT-IN only (HEAVEN_WITH_OLLAMA=1): a 7B model is a big download, so never pull
# it unprompted. Otherwise just point users at the one-command setup.
if ($env:HEAVEN_WITH_OLLAMA -eq '1') {
    if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Ollama (HEAVEN_WITH_OLLAMA=1)..."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install --id Ollama.Ollama -e --source winget --accept-package-agreements --accept-source-agreements 2>$null
        } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
            scoop install ollama 2>$null
        } else {
            Write-Warn "No winget/scoop - install Ollama: https://ollama.com/download"
        }
    }
    if (Get-Command ollama -ErrorAction SilentlyContinue) {
        $Model = if ($env:HEAVEN_OLLAMA_MODEL) { $env:HEAVEN_OLLAMA_MODEL } else { "qwen2.5:7b" }
        Write-Info "Pulling local model $Model (this can take a while)..."
        ollama pull $Model 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Ok "Local model $Model ready" }
        else { Write-Warn "Model pull failed - run later: ollama pull $Model" }
    }
} else {
    Write-Info "Local AI: run 'heaven ai setup' for a private, rate-limit-free model (no API key)"
    Write-Info "  - or set HEAVEN_WITH_OLLAMA=1 to install it during setup."
}

# -- 7. Web UI ----------------------------------------------------------------
Write-Step "Step 7/9 - Building web UI..."

$UiDir = Join-Path $InstallDir 'heaven-ui'
if ($SkipUI) {
    Write-Info "Skipping web UI build (requested)"
} elseif (-not (Test-Path $UiDir)) {
    Write-Warn "heaven-ui directory not found - skipping frontend build"
} elseif (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Warn "npm not found - skipping frontend build"
    Write-Host "    Install Node.js 22.22+ from https://nodejs.org, then:"
    Write-Host "    cd heaven-ui; npm install --legacy-peer-deps; npm run build"
    Write-Host "    The CLI + API work fully without the UI; 'heaven serve' shows a placeholder until it's built."
} else {
    # The whole UI build is best-effort: a broken Node/npm must never abort the
    # installer (which runs under ErrorActionPreference='Stop'), because the CLI
    # and API work fine without the prebuilt UI. Catch every failure -> warn.
    try {
        $nodeVer = (& node --version 2>$null)
        Write-Info "Node $nodeVer detected"
        # react-router 8 requires Node >=22.22.0; warn early if the runtime is older.
        $nodeParsed = $null
        if ([version]::TryParse(($nodeVer -replace '[^0-9.]', ''), [ref]$nodeParsed)) {
            if ($nodeParsed -lt [version]'22.22.0') {
                Write-Warn "Node $nodeVer is too old - the web UI needs Node 22.22+ (react-router 8). Build may fail."
            }
        }
        $BuildLog = Join-Path $UiDir 'build.log'
        Push-Location $UiDir
        try {
            cmd /c "npm install --legacy-peer-deps > `"$BuildLog`" 2>&1"
            if ($LASTEXITCODE -eq 0) { cmd /c "npm run build >> `"$BuildLog`" 2>&1" }
            if ($LASTEXITCODE -eq 0 -and (Test-Path (Join-Path $UiDir 'dist\index.html'))) {
                Write-Ok "Frontend built -> heaven-ui\dist\"
                Remove-Item $BuildLog -ErrorAction SilentlyContinue
            } else {
                Write-Warn "Frontend build failed - see $BuildLog"
                Write-Host "    UI unavailable but the CLI and API work fine."
            }
        } finally {
            Pop-Location
        }
    } catch {
        Write-Warn "Web UI build skipped - $($_.Exception.Message)"
        Write-Host "    UI unavailable but the CLI and API work fine (build later: cd heaven-ui; npm install --legacy-peer-deps; npm run build)."
    }
}

# -- 8. First-run configuration (.env) ----------------------------------------
Write-Step "Step 8/9 - First-run configuration..."

$EnvFile = Join-Path $InstallDir '.env'
if (Test-Path $EnvFile) {
    Write-Ok ".env already present - leaving your configuration untouched"
} else {
    Push-Location $InstallDir
    try {
        & $VenvPython -m heaven.main init --non-interactive
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Created .env with generated credentials (admin password shown above)"
            Write-Info "Change it anytime: web UI -> Settings, or 'heaven config set HEAVEN_ADMIN_PASSWORD'"
        } else {
            Write-Warn "Could not auto-create .env - run 'heaven init' after install"
        }
    } finally {
        Pop-Location
    }
}

# -- 9. Smoke test ------------------------------------------------------------
Write-Step "Step 9/9 - Smoke test..."
$null = & $VenvPython -m heaven.main --version 2>$null
if ($LASTEXITCODE -eq 0) {
    $hv = (& $VenvPython -m heaven.main --version 2>&1 | Select-Object -First 1)
    Write-Ok "CLI smoke test passed: $hv"
} else {
    Write-Warn "CLI smoke test failed - check errors above"
}

# -- Summary ------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "                 INSTALLATION COMPLETE                       " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Warn "Open a NEW terminal (or restart it) so 'heaven' is on PATH."
Write-Host ""
Write-Host "Quick start:" -ForegroundColor White
Write-Host "  heaven --version"
Write-Host "  heaven engage init my-engagement"
Write-Host "  heaven scan -u https://target --i-have-authorization"
Write-Host "  heaven serve                         # web UI -> http://localhost:8443"
Write-Host ""

# Fatal errors already abort via Die (exit 1); reaching here means success. Exit
# explicitly so a tolerated non-zero from an earlier non-fatal step (e.g. an
# optional feature pack) can't leak into a caller's $LASTEXITCODE check.
exit 0
