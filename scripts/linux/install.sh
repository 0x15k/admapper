#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# ADMapper installer — macOS / Linux / Kali / WSL
#
# Usage:
#   ./scripts/install.sh              pipx global install (recommended)
#   ./scripts/install.sh --venv       local .venv install
#   ./scripts/install.sh --dev        venv + dev extras (pytest/ruff)
#   ./scripts/install.sh --force      force reinstall
#   ./scripts/install.sh --uninstall  remove admapper
#
# One-liner (from GitHub):
#   curl -sSL https://raw.githubusercontent.com/0x15k/admapper/main/scripts/install.sh | bash
# ──────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
ok()   { printf "${GREEN}[+]${NC} %s\n" "$*"; }
info() { printf "${CYAN}[*]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()  { printf "${RED}[x]${NC} %s\n" "$*" >&2; }
die()  { err "$@"; exit 1; }

# ── Resolve repo root ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../pyproject.toml" ]]; then
    ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [[ -f "$(pwd)/pyproject.toml" ]]; then
    ROOT="$(pwd)"
else
    ROOT=""
fi

# ── Parse args ──────────────────────────────────────────────────
EXTRA="full"
FORCE=0
USE_VENV=0
UNINSTALL=0

usage() {
    printf "${BOLD}ADMapper Installer${NC}\n"
    cat <<'EOF'

Usage:
  ./scripts/install.sh              Global install via pipx (recommended)
  ./scripts/install.sh --venv       Local .venv install (development)
  ./scripts/install.sh --dev        Dev mode (.venv + pytest + ruff)
  ./scripts/install.sh --force      Force reinstall over existing
  ./scripts/install.sh --uninstall  Remove admapper completely

After install:
  admapper --help
  admapper run -H <DC_IP> -u <user> -p '<pass>'
  admapper doctor
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)       EXTRA="dev"; USE_VENV=1 ;;
        --venv)      USE_VENV=1 ;;
        --force)     FORCE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "Unknown option: $1  (use --help)" ;;
    esac
    shift
done

# ── Python detection ───────────────────────────────────────────
find_python() {
    local py=""
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            py="$candidate"
            break
        fi
    done
    [[ -n "$py" ]] || die "Python 3.11+ not found. Install from https://python.org/downloads"

    local ver major minor
    ver="$($py -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    major="${ver%%.*}"
    minor="${ver#*.}"
    if [[ "$major" -lt 3 ]] || { [[ "$major" -eq 3 ]] && [[ "$minor" -lt 11 ]]; }; then
        die "Python $ver found but 3.11+ is required"
    fi
    PYTHON="$py"
    PYTHON_VER="$ver"
    ok "Python $ver  ($PYTHON)"
}

# ── OS detection ────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Darwin)              OS="macos" ;;
        Linux)               OS="linux" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *)                   OS="linux" ;;
    esac
    # Detect Kali/Parrot specifically (PEP 668 workaround)
    IS_KALI=0
    if [[ "$OS" == "linux" ]] && [[ -f /etc/os-release ]]; then
        if grep -qiE 'kali|parrot' /etc/os-release 2>/dev/null; then
            IS_KALI=1
        fi
    fi
    local detail="$(uname -m)"
    [[ "$IS_KALI" -eq 1 ]] && detail="$detail, Kali/Parrot"
    ok "Platform: $OS  ($detail)"
}

# ── Repo validation ────────────────────────────────────────────
ensure_repo() {
    if [[ -z "$ROOT" ]]; then
        # One-liner mode: try to clone
        if command -v git >/dev/null 2>&1; then
            info "Not in repo — cloning from GitHub..."
            local tmp="/tmp/admapper-install-$$"
            git clone --depth 1 https://github.com/0x15k/admapper.git "$tmp"
            ROOT="$tmp"
        else
            die "Not in admapper repo and git is not available"
        fi
    fi

    cd "$ROOT"

    # Validate layout
    local missing=()
    [[ -f pyproject.toml ]]          || missing+=("pyproject.toml")
    [[ -d admapper ]]                || missing+=("admapper/")
    [[ -f admapper/cli/main.py ]]    || missing+=("admapper/cli/main.py")
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Incomplete repo at $ROOT — missing: ${missing[*]}"
    fi

    mkdir -p workspaces
    ok "Repo: $ROOT"
}

# ── pipx management ────────────────────────────────────────────
ensure_pipx() {
    if command -v pipx >/dev/null 2>&1; then
        ok "pipx found"
        return 0
    fi

    info "Installing pipx..."
    if [[ "$OS" == "macos" ]] && command -v brew >/dev/null 2>&1; then
        brew install pipx 2>/dev/null || $PYTHON -m pip install --user --break-system-packages pipx 2>/dev/null || $PYTHON -m pip install --user pipx
    elif [[ "$IS_KALI" -eq 1 ]]; then
        sudo apt install -y pipx 2>/dev/null || $PYTHON -m pip install --user --break-system-packages pipx 2>/dev/null || $PYTHON -m pip install --user pipx
    else
        $PYTHON -m pip install --user pipx 2>/dev/null || $PYTHON -m pip install --user --break-system-packages pipx
    fi

    # Ensure PATH includes pipx bin dir
    _refresh_path
    pipx ensurepath 2>/dev/null || true
    _refresh_path

    command -v pipx >/dev/null 2>&1 || die "pipx installed but not in PATH. Restart terminal and retry."
    ok "pipx ready"
}

_refresh_path() {
    export PATH="$HOME/.local/bin:$PATH"
    if [[ "$OS" == "macos" ]]; then
        local user_base
        user_base="$($PYTHON -m site --user-base 2>/dev/null || true)"
        [[ -n "$user_base" && -d "$user_base/bin" ]] && export PATH="$user_base/bin:$PATH"
    fi
}

# ── Install: pipx (global) ─────────────────────────────────────
install_pipx() {
    ensure_pipx

    # Auto-detect if already installed → upgrade instead of failing
    local already_installed=0
    if pipx list --short 2>/dev/null | grep -q '^admapper '; then
        already_installed=1
    fi

    if [[ "$already_installed" -eq 1 ]] && [[ "$FORCE" -eq 0 ]]; then
        info "admapper already installed via pipx — upgrading..."
        pipx install --editable ".[${EXTRA}]" --force
    else
        local args=(install --editable ".[${EXTRA}]")
        [[ "$FORCE" -eq 1 ]] && args+=(--force)
        info "pipx ${args[*]}"
        pipx "${args[@]}"
    fi

    pipx ensurepath 2>/dev/null || true
    _refresh_path

    echo ""
    if command -v admapper >/dev/null 2>&1; then
        ok "admapper installed globally!"
        printf "  ${DIM}$(command -v admapper)${NC}\n"
        admapper version 2>/dev/null || true
    else
        ok "admapper installed — restart your terminal or run:"
        echo "  source ~/.zshrc   # zsh"
        echo "  source ~/.bashrc  # bash"
    fi
}

# ── Install: venv (local) ──────────────────────────────────────
install_venv() {
    local venv="$ROOT/.venv"
    info "Creating venv at $venv"

    if ! $PYTHON -m venv "$venv"; then
        if [[ "$IS_KALI" -eq 1 ]]; then
            warn "venv failed — trying: sudo apt install python3-venv"
            sudo apt install -y python3-venv
            $PYTHON -m venv "$venv" || die "venv creation failed"
        else
            die "venv creation failed"
        fi
    fi

    "$venv/bin/pip" install -U pip -q
    "$venv/bin/pip" install -e ".[${EXTRA}]"

    echo ""
    ok "admapper installed in $venv"
    echo ""
    echo "  Activate:  source $venv/bin/activate"
    echo "  Then run:  admapper --help"
}

# ── Uninstall ───────────────────────────────────────────────────
do_uninstall() {
    info "Removing admapper..."
    if command -v pipx >/dev/null 2>&1; then
        pipx uninstall admapper 2>/dev/null && ok "Removed from pipx" || true
    fi
    if [[ -n "$ROOT" && -d "$ROOT/.venv" ]]; then
        rm -rf "$ROOT/.venv"
        ok "Removed .venv"
    fi
    ok "Uninstall complete"
}

# ── Post-install doctor + tips ──────────────────────────────────
post_install() {
    echo ""
    printf "${BOLD}Recommended companion tools (install separately):${NC}\n"
    echo "  pipx install certipy-ad       # AD CS exploitation (ESC1-14)"
    echo "  pipx install pywhisker        # Shadow Credentials"
    echo "  pipx install netexec          # nxc (SMB/WinRM/LDAP)"
    if [[ "$OS" == "macos" ]]; then
        echo "  brew install hashcat john-jumbo libfaketime"
    else
        echo "  sudo apt install -y hashcat john   # Kali/Debian"
    fi

    echo ""
    printf "${BOLD}Quick start:${NC}\n"
    echo "  admapper run -H <DC_IP> -u <user> -p '<pass>'"
    echo "  admapper doctor    # verify installation health"
    echo ""

    # Run doctor if available
    if command -v admapper >/dev/null 2>&1; then
        info "Running admapper doctor..."
        admapper doctor 2>/dev/null || true
    fi
}

# ── Main ───────────────────────────────────────────────────────
main() {
    echo ""
    printf "${BOLD}  ADMapper Installer v0.2.0${NC}\n"
    printf "${DIM}  All-in-one Active Directory pentesting toolkit${NC}\n"
    echo "  ─────────────────────────────────────────────"
    echo ""

    if [[ "$UNINSTALL" -eq 1 ]]; then
        do_uninstall
        exit 0
    fi

    find_python
    detect_os
    ensure_repo
    echo ""

    if [[ "$USE_VENV" -eq 1 ]]; then
        install_venv
    else
        install_pipx
    fi

    post_install
}

main
