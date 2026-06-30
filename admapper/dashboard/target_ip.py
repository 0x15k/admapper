"""Apply target IP changes — workspace state + /etc/hosts sync."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from admapper.report.engagement import _load_json
from admapper.support.system_hosts import (
    HostsSyncResult,
    HostsSyncStatus,
    ensure_system_hosts_entry,
    format_hosts_sync_message,
)

if TYPE_CHECKING:
    from admapper.support.session import Session


def first_host_token(value: str | None) -> str:
    """First host/IP from a workspace hosts field; safe when empty or whitespace."""
    parts = (value or "").strip().split()
    return parts[0] if parts else ""


def resolve_dc_fqdn(session: Session, ip: str | None = None) -> str | None:
    """Best-effort DC FQDN from scan artefacts or workspace domain."""
    if session.workspace is None:
        return None

    ws_path = session.workspaces.path_for(session.workspace.name)
    target_ip = first_host_token(ip or session.workspace.hosts)

    report = _load_json(ws_path / "unauth_scan.json") or {}
    for host in report.get("hosts") or []:
        addr = str(host.get("address") or "")
        fqdn = str(host.get("hostname") or "").strip().rstrip(".")
        if not fqdn or fqdn in {"-", "sin PTR"}:
            continue
        if host.get("is_domain_controller"):
            return fqdn
        if target_ip and addr == target_ip:
            return fqdn

    inv = _load_json(ws_path / "auth_inventory.json") or {}
    for dc in inv.get("domain_controllers") or inv.get("dcs") or []:
        if isinstance(dc, dict):
            name = str(dc.get("name") or dc.get("hostname") or "").strip().rstrip(".")
            if name:
                return name
        elif isinstance(dc, str) and dc.strip():
            return dc.strip().rstrip(".")

    domain = (session.workspace.domain or "").strip().lower().rstrip(".")
    if domain:
        return f"dc01.{domain}"

    return None


def sync_dc_hosts_for_session(session: Session, ip: str | None = None) -> HostsSyncResult | None:
    """Update /etc/hosts when DC IP or FQDN mapping is known (survives DC IP changes)."""
    if session.workspace is None:
        return None

    target_ip = first_host_token(ip or session.workspace.hosts)
    if not target_ip:
        return None

    fqdn = resolve_dc_fqdn(session, target_ip)
    if not fqdn:
        return HostsSyncResult(
            HostsSyncStatus.SKIPPED,
            target_ip,
            "",
            detail="DC FQDN unknown — run Discovery first or set DOMAIN",
        )

    return ensure_system_hosts_entry(target_ip, fqdn, use_sudo=True)


def apply_target_ip_change(session: Session, new_ip: str) -> dict[str, Any]:
    """Persist target IP and sync /etc/hosts when FQDN is available."""
    from admapper.cli.commands import dispatch

    ip = first_host_token(new_ip)
    if not ip:
        return {"ip": "", "hosts_sync": None, "hosts_message": None}

    old_ip = first_host_token(session.workspace.hosts if session.workspace else None)
    dispatch(session, f"set hosts {ip}")
    session.persist_workspace()

    result: HostsSyncResult | None = None
    if ip != old_ip or old_ip:
        result = sync_dc_hosts_for_session(session, ip)

    message = format_hosts_sync_message(result) if result else None
    if result and result.status == HostsSyncStatus.SKIPPED:
        message = None
    return {
        "ip": ip,
        "fqdn": resolve_dc_fqdn(session, ip),
        "hosts_sync": result.status.value if result else None,
        "hosts_message": message,
    }
