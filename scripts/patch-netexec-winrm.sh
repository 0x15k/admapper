#!/usr/bin/env bash
# Patch NetExec winrm: implement kerberos_login (upstream missing) + fix false-positive kcache auth.
set -euo pipefail

NXC_VENV="${1:-${HOME}/.local/pipx/venvs/netexec}"

if [[ ! -d "$NXC_VENV" ]]; then
  echo "✗ netexec venv not found at $NXC_VENV" >&2
  echo "  usage: $0 <path/to/netexec/venv>" >&2
  echo "  install example: pipx install --python python3.13 git+https://github.com/Pennyw0rth/NetExec" >&2
  exit 1
fi

PYTHON_BIN="${NXC_VENV}/bin/python"
if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "✗ python interpreter not found at $PYTHON_BIN" >&2
  exit 1
fi

SITE_PACKAGES="$($PYTHON_BIN -c 'import site; print(site.getsitepackages()[0])')"
WINRM_PY="${SITE_PACKAGES}/nxc/protocols/winrm.py"
CONN_PY="${SITE_PACKAGES}/nxc/connection.py"

if [[ ! -f "$WINRM_PY" ]]; then
  echo "✗ netexec not installed in $NXC_VENV (missing $WINRM_PY)" >&2
  exit 1
fi

if grep -q "def kerberos_login" "$WINRM_PY"; then
  echo "✓ kerberos_login already present in winrm.py"
else
  echo "==> Adding kerberos_login to winrm.py"
  "$PYTHON_BIN" - "$WINRM_PY" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
marker = "    def hash_login(self, domain, username, ntlm_hash):"
insert = '''    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.username = username
        self.domain = domain
        realm = domain.upper() if domain else ""
        principal = username if "@" in username else f"{username}@{realm}"
        try:
            self.conn = Client(
                self.host,
                port=self.port,
                auth="kerberos",
                username=principal,
                password=password if password and not useCache else None,
                ssl=self.ssl,
                cert_validation=False,
            )
            self.check_if_admin()
            self.logger.success(f"{principal} {self.mark_pwned()}")
            self.db.add_credential("plaintext", domain, self.username, password or "kcache")
            user_id = self.db.get_credential("plaintext", domain, self.username, password or "kcache")
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)
            if self.admin_privs:
                self.db.add_admin_user("plaintext", domain, self.username, password or "kcache", self.host, user_id=user_id)
            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except Exception as e:
            self.logger.fail(f"{principal}: {e!s}")
            return False

'''
if marker not in text:
    raise SystemExit("marker not found in winrm.py — nxc version changed?")
path.write_text(text.replace(marker, insert + marker, 1))
print("patched winrm.py")
PY
fi

if grep -q "if not self.kerberos_login" "$CONN_PY"; then
  echo "✓ connection.py kcache check already patched"
else
  echo "==> Fixing false-positive kcache auth in connection.py"
  "$PYTHON_BIN" - "$CONN_PY" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = """                self.kerberos_login(self.domain, username, password, "", "", self.kdcHost, True)
                self.logger.info("Successfully authenticated using Kerberos cache")
                return True"""
new = """                if not self.kerberos_login(self.domain, username, password, "", "", self.kdcHost, True):
                    return False
                self.logger.info("Successfully authenticated using Kerberos cache")
                return True"""
if old not in text:
    raise SystemExit("connection.py pattern not found — already patched or nxc version changed?")
path.write_text(text.replace(old, new, 1))
print("patched connection.py")
PY
fi

echo "Done. Requires: python3 -m pip install gssapi krb5 (in netexec venv)"
"$PYTHON_BIN" -m pip install -q gssapi krb5 2>/dev/null || true
echo "Try: nxc winrm <DC_FQDN> -u <user> -k --use-kcache -d <DOMAIN> -x whoami"
