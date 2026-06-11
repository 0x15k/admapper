#!/usr/bin/env bash
# ADMapper — instalación oficial (pipx = comando global sin activar venv)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

validate_repo_layout() {
  local missing=()
  [[ -f "$ROOT/pyproject.toml" ]] || missing+=("pyproject.toml")
  [[ -f "$ROOT/admapper/__init__.py" ]] || missing+=("admapper/__init__.py")
  [[ -f "$ROOT/admapper/cli/main.py" ]] || missing+=("admapper/cli/main.py")
  [[ -f "$ROOT/scripts/install.sh" ]] || missing+=("scripts/install.sh")
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "✗ Raíz de repo incompleta en: $ROOT" >&2
    echo "  Faltan: ${missing[*]}" >&2
    if [[ -f "$ROOT/../pyproject.toml" && -d "$ROOT/../admapper" ]]; then
      echo "" >&2
      echo "  Parece que estás dentro del paquete Python, no en la raíz del repo." >&2
      echo "  Ejecuta desde:  cd $(cd "$ROOT/.." && pwd)" >&2
      echo "  Luego:          ./scripts/install.sh" >&2
    fi
    exit 1
  fi
  mkdir -p "$ROOT/workspaces"
}

validate_repo_layout

EXTRA="full"
FORCE=0
USE_VENV=0

usage() {
  cat <<'EOF'
ADMapper installer

Uso:
  ./scripts/install.sh              Instala admapper globalmente con pipx ([full])
  ./scripts/install.sh --dev        Incluye pytest/ruff ([dev])
  ./scripts/install.sh --venv       Instala en .venv/ (desarrollo clásico)
  ./scripts/install.sh --force      Reinstala si ya existe en pipx
  ./scripts/install.sh --help

Tras pipx: source ~/.zprofile  (o terminal nueva)
El comando queda en PATH:  admapper run -H <ip> -u <user> -p '<pass>' --full
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) EXTRA="dev" ;;
    --venv) USE_VENV=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "✗ python3 no encontrado (requiere Python 3.11+)" >&2
  exit 1
fi

PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER#*.}"
if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 11 ]]; then
  echo "✗ Python $PY_VER — se requiere 3.11+" >&2
  exit 1
fi

ensure_pipx() {
  if command -v pipx >/dev/null 2>&1; then
    return 0
  fi
  echo "→ pipx no encontrado — instalando…"
  if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    brew install pipx
    pipx ensurepath
  else
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
  fi
  if ! command -v pipx >/dev/null 2>&1; then
    echo "✗ pipx instalado pero no está en PATH." >&2
    echo "  Ejecuta:  source ~/.zshrc   (o reinicia la terminal)" >&2
    exit 1
  fi
}

install_venv() {
  echo "→ Instalación en .venv/ (desarrollo)"
  VENV="$ROOT/.venv"
  if ! python3 -m venv "$VENV"; then
    echo "✗ no se pudo crear venv — en Kali: sudo apt install -y python3-venv" >&2
    exit 1
  fi
  VENV_PIP="$VENV/bin/pip"
  VENV_ADMAPPER="$VENV/bin/admapper"
  if [[ ! -x "$VENV_PIP" ]]; then
    echo "✗ venv incompleto: falta $VENV_PIP" >&2
    exit 1
  fi
  # Never use system pip on Kali (PEP 668) — always the venv binary.
  "$VENV_PIP" install -U pip
  "$VENV_PIP" install -e ".[${EXTRA}]"
  echo ""
  echo "✓ ADMapper en $VENV"
  echo "  Activa en cada terminal:"
  echo "    source $VENV/bin/activate"
  echo "  Verifica que pip sea del venv (no debe fallar PEP 668):"
  echo "    which pip    # → $VENV/bin/pip"
  echo "    admapper scan --ip-dc <DC_IP>"
  echo ""
  "$VENV_ADMAPPER" doctor || true
}

pipx_bin_dir() {
  python3 -m site --user-base 2>/dev/null | awk '{print $0 "/bin"}'
}

ensure_path() {
  # pipx ensurepath writes to ~/.zprofile (macOS zsh) or ~/.bashrc
  pipx ensurepath >/dev/null 2>&1 || true
  local bindir
  bindir="$(pipx_bin_dir)"
  if [[ -d "$bindir" ]]; then
    export PATH="$bindir:$PATH"
  fi
}

resolve_admapper_bin() {
  if command -v admapper >/dev/null 2>&1; then
    command -v admapper
    return 0
  fi
  local bindir candidate
  bindir="$(pipx_bin_dir)"
  candidate="$bindir/admapper"
  if [[ -x "$candidate" ]]; then
    echo "$candidate"
    return 0
  fi
  return 1
}

install_pipx() {
  ensure_pipx
  ensure_path

  local args=(install --editable ".[${EXTRA}]")
  if [[ "$FORCE" -eq 1 ]]; then
    args+=(--force)
  fi
  echo "→ pipx ${args[*]}"
  pipx "${args[@]}"

  ensure_path
  local admapper_bin bindir
  admapper_bin="$(resolve_admapper_bin || true)"
  bindir="$(pipx_bin_dir)"

  echo ""
  echo "✓ ADMapper instalado globalmente"
  if [[ -n "$admapper_bin" ]]; then
    echo "  Binario: $admapper_bin"
    "$admapper_bin" version
  fi

  if ! command -v admapper >/dev/null 2>&1; then
    echo ""
    echo "! El comando 'admapper' no está en PATH de esta terminal."
    echo "  Ejecuta UNA de estas opciones:"
    echo ""
    echo "  1) Cargar PATH de pipx (recomendado):"
    echo "       source ~/.zprofile"
    echo "     o abre una terminal nueva."
    echo ""
    echo "  2) Añadir permanentemente a ~/.zshrc:"
    echo "       echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.zshrc"
    echo "       source ~/.zshrc"
    echo ""
    echo "  3) Usar ruta completa ahora:"
    echo "       $admapper_bin version"
  fi

  echo ""
  echo "Herramientas externas recomendadas (no incluidas en pipx):"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "  brew install rust               # requerido por NetExec en macOS"
    echo "  # Python 3.14: usar 3.13 o forzar build PyO3 (aardwolf):"
    echo "  brew install python@3.13"
    echo "  pipx install --python python3.13 git+https://github.com/Pennyw0rth/NetExec"
    echo "  # alternativa 3.14:"
    echo "  PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 pipx install git+https://github.com/Pennyw0rth/NetExec"
    echo "  # guía: https://www.netexec.wiki/getting-started/installation/installation-for-mac"
  else
    echo "  pipx install netexec          # nxc"
  fi
  echo "  brew install hashcat john-jumbo   # macOS"
  echo "  brew install libfaketime          # macOS — Kerberos clock offset sin root"
  echo ""
  echo "Kerberos (cualquier engagement AD):"
  echo "  admapper creds verify <id>        # detecta skew y sugiere sync con el DC"
  echo "  admapper run ... --clock-skew '+7h'   # offset vía libfaketime si no puedes usar sudo"
  echo ""
  echo "Validar instalación:     admapper doctor"
  if [[ -n "$admapper_bin" ]]; then
    "$admapper_bin" doctor || true
  fi
}

if [[ "$USE_VENV" -eq 1 ]]; then
  install_venv
else
  install_pipx
fi
