#!/usr/bin/env bash
# Sync admapper source to Kali and reinstall editable package.
set -euo pipefail

SRC="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
DEST="${2:-$HOME/admapper-src}"
VENV="${ADMAPPER_VENV:-$HOME/admapper-venv}"

echo "→ source: $SRC"
echo "→ dest:   $DEST"

mkdir -p "$DEST"
rsync -a --delete \
  --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' --exclude '.git' \
  "$SRC/" "$DEST/"

if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi

"$VENV/bin/pip" install -U pip wheel
"$VENV/bin/pip" install -e "$DEST"

echo ""
echo "✓ synced → $DEST"
echo "  source $VENV/bin/activate"
echo "  admapper version   # expect 0.1.1+"
echo "  admapper brief -w <workspace> --auto"
