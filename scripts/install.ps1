# ADMapper — instalación en Windows (venv; pipx opcional con pipx install -e ".[full]")
param(
    [switch]$Dev,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if ($Help) {
    Write-Host @"
ADMapper installer (Windows)

  .\scripts\install.ps1           venv + pip install -e ".[full]"
  .\scripts\install.ps1 -Dev      extras de desarrollo

Global (cualquier terminal):
  pip install pipx
  pipx install --editable ".[full]"
"@
    exit 0
}

$Extra = if ($Dev) { "dev" } else { "full" }

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "python no encontrado — instala Python 3.11+"
}

python -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e ".[$Extra]"

Write-Host ""
Write-Host "ADMapper instalado en .venv"
Write-Host "Activa:  .\.venv\Scripts\Activate.ps1"
Write-Host "O usa pipx para comando global:  pipx install --editable `".[full]`""
