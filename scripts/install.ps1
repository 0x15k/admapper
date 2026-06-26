# ADMapper installer wrapper for Windows.
# Runs the unified Python installer.
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $python) {
    Write-Error "Python 3.11+ not found. Install from https://python.org/downloads"
    exit 1
}

$installPy = Join-Path $PSScriptRoot "install.py"
& $python.Source $installPy @args
