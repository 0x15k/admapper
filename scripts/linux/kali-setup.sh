#!/usr/bin/env bash
# Install admapper in a venv on Kali (PEP 668 blocks system pip).
set -euo pipefail

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
VENV="${ADMAPPER_VENV:-$HOME/admapper-venv}"

echo "→ repo: $REPO"
echo "→ venv: $VENV"

sudo apt-get update -qq
sudo apt-get install -y python3-venv python3-pip krb5-user libfaketime

if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi

"$VENV/bin/pip" install -U pip wheel
"$VENV/bin/pip" install -e "$REPO"

echo ""
echo "✓ admapper installed in venv"
echo ""
echo "  source $VENV/bin/activate"
echo "  admapper run -H <ip> -u <user> -p '<pass>' -w <workspace> --clock-skew '+7h'"
echo ""
echo "  # compact map (default); full phases: add -v"
echo "  admapper analyst -w <workspace> --clock-skew '+7h'"
echo ""
echo "  which kinit kvno   # required for gMSA exploit"
