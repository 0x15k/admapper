#!/usr/bin/env bash
# macOS: install pypsrp + gssapi + krb5 for `admapper winrm` and optionally fix evil-winrm gem.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Homebrew MIT Kerberos"
if ! brew list krb5 &>/dev/null; then
  brew install krb5
fi

PY=""
for candidate in \
  "$HOME/.local/pipx/venvs/admapper/bin/python3.13" \
  "$HOME/.local/pipx/venvs/admapper/bin/python3" \
  python3.13 python3; do
  if command -v "$candidate" &>/dev/null; then
    PY="$candidate"
    break
  fi
done

if [[ -z "$PY" ]]; then
  echo "✗ python3 not found" >&2
  exit 1
fi

echo "==> Python WinRM deps ($PY)"
"$PY" -m pip install -U pypsrp gssapi krb5

echo "==> Verify imports"
"$PY" -c "import pypsrp, gssapi, krb5; print('pypsrp+gssapi+krb5 OK')"

if command -v evil-winrm &>/dev/null && command -v gem &>/dev/null; then
  echo "==> Rebuild Ruby gssapi against MIT krb5 (evil-winrm)"
  KRB5_PREFIX="$(brew --prefix krb5)"
  gem uninstall gssapi -aIx 2>/dev/null || true
  gem install gssapi -- --with-gssapi-dir="$KRB5_PREFIX" || {
    echo "⚠ gem gssapi rebuild failed — use: admapper winrm (recommended on macOS)"
  }
else
  echo "ℹ evil-winrm/gem not found — skip Ruby gssapi rebuild"
fi

cat <<EOF

Done. Use WinRM on macOS:

  sudo sntp -sS <DC_IP>
  admapper winrm -H <DC_IP> -d logging.htb -u svc_recovery -p 'Em3rg3ncyPa\$\$2026'
  admapper winrm -H DC01.logging.htb -d logging.htb -u svc_recovery -p '...' -x whoami

Optional: patch nxc winrm Kerberos bug:
  $ROOT/scripts/patch-netexec-winrm.sh

EOF
