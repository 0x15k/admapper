# ──────────────────────────────────────────────────────────────
# ADMapper installer — Windows (PowerShell 5.1+)
#
# Usage:
#   .\scripts\install.ps1              pipx global install (recommended)
#   .\scripts\install.ps1 -Venv        local .venv install
#   .\scripts\install.ps1 -Dev         venv + dev extras
#   .\scripts\install.ps1 -Force       force reinstall
#   .\scripts\install.ps1 -Uninstall   remove admapper
# ──────────────────────────────────────────────────────────────
param(
    [switch]$Venv,
    [switch]$Dev,
    [switch]$Force,
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# ── Colors ──────────────────────────────────────────────────────
function Write-Ok    { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Info  { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Warn  { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "[x] $m" -ForegroundColor Red }
function Write-Die   { param($m) Write-Err $m; exit 1 }

# ── Help ────────────────────────────────────────────────────────
if ($Help) {
    Write-Host ""
    Write-Host "  ADMapper Installer (Windows)" -ForegroundColor White
    Write-Host "  All-in-one Active Directory pentesting toolkit" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  .\scripts\install.ps1              Global install via pipx (recommended)"
    Write-Host "  .\scripts\install.ps1 -Venv        Local .venv install"
    Write-Host "  .\scripts\install.ps1 -Dev         Dev mode (.venv + pytest + ruff)"
    Write-Host "  .\scripts\install.ps1 -Force       Force reinstall"
    Write-Host "  .\scripts\install.ps1 -Uninstall   Remove admapper"
    Write-Host ""
    Write-Host "After install:" -ForegroundColor Cyan
    Write-Host "  admapper --help"
    Write-Host "  admapper run -H <DC_IP> -u <user> -p '<pass>'"
    Write-Host "  admapper doctor"
    Write-Host ""
    exit 0
}

# ── Resolve repo root ──────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
Set-Location $Root

if (-not (Test-Path "$Root\pyproject.toml")) {
    Write-Die "Not in admapper repo — pyproject.toml not found at $Root"
}

# ── Config ──────────────────────────────────────────────────────
$Extra = if ($Dev) { "dev" } else { "full" }
$UseVenv = $Venv -or $Dev

Write-Host ""
Write-Host "  ADMapper Installer v0.2.0" -ForegroundColor White
Write-Host "  All-in-one Active Directory pentesting toolkit" -ForegroundColor DarkGray
Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── Uninstall ───────────────────────────────────────────────────
if ($Uninstall) {
    Write-Info "Removing admapper..."
    try { pipx uninstall admapper 2>$null; Write-Ok "Removed from pipx" } catch {}
    if (Test-Path "$Root\.venv") {
        Remove-Item -Recurse -Force "$Root\.venv"
        Write-Ok "Removed .venv"
    }
    Write-Ok "Uninstall complete"
    exit 0
}

# ── Python detection ───────────────────────────────────────────
$Python = $null
foreach ($candidate in @("python3", "python")) {
    try {
        $ver = & $candidate -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver) {
            $parts = $ver.Split('.')
            $major = [int]$parts[0]
            $minor = [int]$parts[1]
            if ($major -ge 3 -and $minor -ge 11) {
                $Python = $candidate
                break
            }
        }
    } catch {}
}

if (-not $Python) {
    Write-Die "Python 3.11+ not found. Install from https://python.org/downloads"
}

Write-Ok "Python $ver  ($Python)"

# ── pipx (global install) ──────────────────────────────────────
function Ensure-Pipx {
    if (Get-Command pipx -ErrorAction SilentlyContinue) {
        Write-Ok "pipx found"
        return
    }
    Write-Info "Installing pipx..."
    & $Python -m pip install --user pipx
    & $Python -m pipx ensurepath

    # Refresh PATH for this session
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$userPath;$env:Path"

    if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
        Write-Die "pipx installed but not in PATH. Restart PowerShell and retry."
    }
    Write-Ok "pipx ready"
}

function Install-Pipx {
    Ensure-Pipx

    $installArgs = @("install", "--editable", ".[$Extra]")
    if ($Force) { $installArgs += "--force" }

    Write-Info "pipx $($installArgs -join ' ')"
    & pipx @installArgs

    pipx ensurepath 2>$null

    Write-Host ""
    if (Get-Command admapper -ErrorAction SilentlyContinue) {
        Write-Ok "admapper installed globally!"
        & admapper version
    } else {
        Write-Ok "admapper installed — restart PowerShell or run:"
        Write-Host "  `$env:Path = [Environment]::GetEnvironmentVariable('Path','User') + ';' + `$env:Path"
    }
}

# ── venv (local install) ───────────────────────────────────────
function Install-Venv {
    $venvPath = "$Root\.venv"
    Write-Info "Creating venv at $venvPath"

    & $Python -m venv $venvPath
    if (-not $?) { Write-Die "venv creation failed" }

    & "$venvPath\Scripts\pip.exe" install -U pip -q
    & "$venvPath\Scripts\pip.exe" install -e ".[$Extra]"

    Write-Host ""
    Write-Ok "admapper installed in $venvPath"
    Write-Host ""
    Write-Host "  Activate:  .\$venvPath\Scripts\Activate.ps1"
    Write-Host "  Then run:  admapper --help"
}

# ── Post-install ────────────────────────────────────────────────
function Show-PostInstall {
    Write-Host ""
    Write-Host "Recommended external tools:" -ForegroundColor White
    Write-Host "  pipx install netexec certipy-ad"
    Write-Host "  choco install hashcat            # or winget"
    Write-Host ""
    Write-Host "Quick start:" -ForegroundColor White
    Write-Host "  admapper run -H <DC_IP> -u <user> -p '<pass>'"
    Write-Host "  admapper doctor    # verify installation health"
    Write-Host ""

    if (Get-Command admapper -ErrorAction SilentlyContinue) {
        Write-Info "Running admapper doctor..."
        try { & admapper doctor } catch {}
    }
}

# ── Main ───────────────────────────────────────────────────────
if ($UseVenv) {
    Install-Venv
} else {
    Install-Pipx
}

Show-PostInstall
