#!/usr/bin/env bash
# ADMapper installer wrapper for macOS / Linux / WSL.
# Runs the unified Python installer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

find_python() {
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return
        fi
    done
    echo "Python 3.11+ not found. Install from https://python.org/downloads" >&2
    exit 1
}

PYTHON="$(find_python)"
exec "$PYTHON" "$SCRIPT_DIR/install.py" "$@"
