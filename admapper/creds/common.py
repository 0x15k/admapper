from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.stores.credentials import CredentialStore
from admapper.stores.hosts import HostsStore
from admapper.models.credential import CredentialStatus, CredentialType

if TYPE_CHECKING:
    from admapper.support.session import Session


def resolve_dc_fqdn(ws_path: str | None, domain: str | None, *, fallback_ip: str | None = None) -> str:
    """FQDN for Kerberos LDAP SPN (ldap/DC01.domain) — IP alone causes KDC_ERR_S_PRINCIPAL_UNKNOWN."""
    import json
    from pathlib import Path

    domain_key = (domain or "").lower()
    if ws_path:
        ws = Path(ws_path)

        inv_path = ws / "auth_inventory.json"
    else:
        inv_path = Path("/nonexistent")

    if inv_path.is_file():
        try:
            data = json.loads(inv_path.read_text(encoding="utf-8"))
            for computer in data.get("computers") or []:
                dns_host = str(computer.get("dns_host") or "").lower()
                name = str(computer.get("name") or "").lower()
                dn = str(computer.get("dn") or "").lower()
                if "domain controllers" in dn or name == "dc01":
                    if dns_host:
                        return dns_host
                    if name and domain_key:
                        return f"{name}.{domain_key}"
        except (json.JSONDecodeError, OSError):
            pass

    if ws_path:
        for path_name in ("graph.json", "unauth_scan.json"):
            data_path = ws / path_name
            if not data_path.is_file():
                continue
            try:
                data = json.loads(data_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            for key in ("computers", "hosts", "nodes"):
                for item in data.get(key) or []:
                    if not isinstance(item, dict):
                        continue
                    dns_host = str(
                        item.get("dns_host")
                        or item.get("dnsHostName")
                        or item.get("hostname")
                        or ""
                    ).lower()
                    name = str(item.get("name") or "").lower()
                    if dns_host and ("dc" in dns_host or "dc01" in dns_host):
                        return dns_host
                    if name == "dc01" and domain_key:
                        return f"dc01.{domain_key}"

    if domain_key:
        return f"dc01.{domain_key}"
    return fallback_ip or "localhost"


def pick_dc_fqdn(session: Session, *, domain: str | None = None) -> str | None:
    if session.workspace is None:
        return None
    ws_path = str(session.workspaces.path_for(session.workspace.name))
    domain_key = domain or session.workspace.domain
    fqdn = resolve_dc_fqdn(ws_path, domain_key, fallback_ip=pick_dc_ip(session))
    hosts_store = HostsStore(session.workspaces, session.workspace.name)
    for host in hosts_store.list():
        if host.hostname and host.is_domain_controller:
            return host.hostname.lower()
    return fqdn


def pick_dc_ip(session: Session) -> str | None:
    if session.workspace is None:
        return None
    hosts_store = HostsStore(session.workspaces, session.workspace.name)
    hosts = hosts_store.list()
    dcs = [h for h in hosts if h.is_domain_controller and 88 in h.open_ports]
    if not dcs:
        dcs = [h for h in hosts if 88 in h.open_ports or 389 in h.open_ports]
    if not dcs:
        fallback = str(session.workspace.hosts or "").strip()
        return fallback or None
    return dcs[0].address


def workspace_password_cred(session: Session, domain: str) -> tuple[str, str] | None:
    """Return (username, password) from workspace credentials if available."""
    if session.workspace is None:
        return None
    store = CredentialStore(session.workspaces, session.workspace.name)
    domain_lower = domain.lower()
    for cred in store.list():
        if cred.cred_type != CredentialType.PASSWORD:
            continue
        if cred.status == CredentialStatus.INVALID:
            continue
        cred_domain = (cred.domain or domain).lower()
        if cred_domain != domain_lower:
            continue
        if cred.secret:
            return cred.username, cred.secret
    return None


def _valid_nthash(value: str) -> bool:
    h = value.lower().strip()
    return len(h) == 32 and h.isalnum() and not h.startswith("aes128")


def collect_gained_hashes(ws_path: str | Path) -> list[tuple[str, str]]:
    """Machine account hashes from exploit_log.json and valid NTLM credentials."""
    ws = Path(ws_path)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(account: str, nthash: str) -> None:
        if not account or not _valid_nthash(nthash):
            return
        user = account if account.endswith("$") else f"{account}$"
        key = user.lower()
        if key in seen:
            return
        seen.add(key)
        out.append((user, nthash.lower()))

    log_path = ws / "exploit_log.json"
    if log_path.is_file():
        try:
            data = json.loads(log_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        for item in data.get("new_hashes") or []:
            add(str(item.get("account", "")), str(item.get("nthash", "")))

    cred_path = ws / "credentials.json"
    if cred_path.is_file():
        try:
            cred_data = json.loads(cred_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            cred_data = {}
        for cred in cred_data.get("credentials") or []:
            if str(cred.get("type", "")).lower() != "ntlm":
                continue
            if str(cred.get("status")) != "valid":
                continue
            secret = str(cred.get("secret") or cred.get("password") or "")
            add(str(cred.get("username", "")), secret)

    return out


def resolve_winrm_host_for_account(
    account: str,
    ws_path: str | Path | None,
    domain: str | None,
    *,
    fallback_ip: str | None = None,
) -> str:
    """Best-effort WinRM target hostname for a machine/gMSA account."""
    base = account.rstrip("$").lower()
    domain_l = (domain or "").lower().rstrip(".")
    ws = Path(ws_path) if ws_path else None

    is_gmsa = base.startswith("msa_") or base.startswith("gmsa_")
    if ws:
        inv_path = ws / "auth_inventory.json"
        if inv_path.is_file():
            try:
                data = json.loads(inv_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
            for computer in data.get("computers") or []:
                name = str(computer.get("name") or "").lower().rstrip("$")
                dn = str(computer.get("dn") or "").lower()
                if name == base:
                    if "managed service accounts" in dn or "msas" in dn:
                        is_gmsa = True
                        break
                    dns_host = str(computer.get("dns_host") or computer.get("dnsHostName") or "")
                    if dns_host:
                        return dns_host.lower()

        for path_name in ("postex_scan.json", "unauth_scan.json"):
            data_path = ws / path_name
            if not data_path.is_file():
                continue
            try:
                data = json.loads(data_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            for key in ("hosts", "findings", "computers"):
                for item in data.get(key) or []:
                    if not isinstance(item, dict):
                        continue
                    hostname = str(
                        item.get("hostname")
                        or item.get("dns_host")
                        or item.get("target_host")
                        or ""
                    ).lower()
                    short = hostname.split(".", 1)[0] if hostname else ""
                    if short == base and hostname:
                        return hostname

    if domain_l and base and not is_gmsa:
        return f"{base}.{domain_l}"

    return resolve_dc_fqdn(str(ws) if ws else None, domain, fallback_ip=fallback_ip) or fallback_ip or base



def format_evil_winrm_pth(
    *,
    account: str,
    nthash: str,
    domain: str | None,
    ws_path: str | Path | None = None,
    fallback_ip: str | None = None,
) -> tuple[str, str]:
    """Return (host, evil-winrm Pass-the-Hash command)."""
    user = account if account.endswith("$") else f"{account}$"
    host = resolve_winrm_host_for_account(
        user,
        ws_path,
        domain,
        fallback_ip=fallback_ip,
    )
    domain_l = (domain or "").lower().rstrip(".")
    # evil-winrm has no -d; embed domain in the username for NTLM PTH.
    user_arg = f"{domain_l}\\{user}" if domain_l else user
    cmd = f"evil-winrm -i {host} -u '{user_arg}' -H {nthash}"
    return host, cmd


def format_admapper_winrm_pth(
    *,
    account: str,
    nthash: str,
    domain: str | None,
    ws_path: str | Path | None = None,
    fallback_ip: str | None = None,
    command: str = "whoami",
) -> tuple[str, str]:
    """Return (host, admapper winrm Pass-the-Hash command — no --dc-ip)."""
    host, _ = format_evil_winrm_pth(
        account=account,
        nthash=nthash,
        domain=domain,
        ws_path=ws_path,
        fallback_ip=fallback_ip,
    )
    user = account if account.endswith("$") else f"{account}$"
    domain_l = (domain or "").lower().rstrip(".")
    cmd = (
        f"admapper winrm -H {host} -d {domain_l} -u '{user}' "
        f"--hash {nthash} -x {command}"
    )
    return host, cmd


def username_from_kerberos_hash(line: str) -> str:
    """Best-effort username extraction from hashcat krb5 lines."""
    star_match = re.search(r"\$krb5tgs\$23\$\*([^$*]+)\$", line)
    if star_match:
        return star_match.group(1)
    asrep_match = re.search(r"\$krb5asrep\$23\$([^:$]+)", line)
    if asrep_match:
        raw = asrep_match.group(1)
        return raw.split("@", 1)[0] if "@" in raw else raw
    if ":" in line and not line.startswith("$"):
        prefix = line.split(":", 1)[0]
        if "@" in prefix:
            return prefix.split("@", 1)[0]
        if "\\" in prefix:
            return prefix.split("\\", 1)[1]
        return prefix
    return "unknown"


def spn_from_tgs_hash(line: str) -> str | None:
    """Extract SPN from hashcat $krb5tgs$23$*user$realm$spn* format."""
    match = re.search(r"\$krb5tgs\$23\$\*[^$]+\$[^$]+\$([^*]+)\*", line)
    if match:
        return match.group(1)
    return None


def apply_cracked_credentials(
    session: Session,
    domain: str,
    cracked: dict[str, str],
    *,
    source: str,
) -> list[tuple[str, str]]:
    if session.workspace is None:
        return []
    creds = CredentialStore(session.workspaces, session.workspace.name)
    saved: list[tuple[str, str]] = []
    for user_key, password in cracked.items():
        username = user_key
        if "@" in user_key:
            username = user_key.split("@", 1)[0]
        if "\\" in username:
            username = username.split("\\", 1)[1]
        cred = creds.add(
            username,
            password,
            domain=domain,
            cred_type=CredentialType.PASSWORD,
            source=source,
        )
        creds.mark_status(cred.id, CredentialStatus.UNVERIFIED)
        saved.append((username, password))
    return saved
