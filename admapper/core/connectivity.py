from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.core.reachability import check_target_reachable
from admapper.creds.common import pick_dc_ip

if TYPE_CHECKING:
    from admapper.core.session import Session

_PROBE_PORTS = (445, 5985, 389)


class TargetUnreachableError(RuntimeError):
    """Target host is not reachable over TCP (VPN off, machine stopped, wrong IP)."""

    def __init__(self, host: str, detail: str = "") -> None:
        self.host = host
        self.detail = detail
        msg = f"{host} unreachable" if host else "no target host"
        if detail:
            msg = f"{msg}: {detail}"
        super().__init__(msg)


def resolve_target_hosts(session: Session) -> list[str]:
    """Candidate target IPs for reachability probes."""
    if session.workspace is None:
        return []

    seen: set[str] = set()
    ordered: list[str] = []

    def add(ip: str | None) -> None:
        if not ip or not ip[0].isdigit() or ip in seen:
            return
        seen.add(ip)
        ordered.append(ip)

    add(pick_dc_ip(session))
    if session.workspace.hosts:
        from admapper.recon.targets import parse_targets

        for ip in parse_targets(session.workspace.hosts):
            add(ip)

    from admapper.core.hosts import HostsStore

    for host in HostsStore(session.workspaces, session.workspace.name).list():
        add(host.address)

    return ordered


def probe_host_reachable(
    host: str,
    *,
    ports: tuple[int, ...] = _PROBE_PORTS,
    timeout: float = 3.0,
) -> tuple[bool, str]:
    """Return (reachable, detail) after trying common AD service ports."""
    return check_target_reachable(host, ports=ports, timeout=timeout)


def require_target_reachable(
    session: Session,
    *,
    host: str | None = None,
    timeout: float = 3.0,
) -> str:
    """Probe target; return reachable IP or raise TargetUnreachableError."""
    candidates = [host] if host else resolve_target_hosts(session)
    if not candidates:
        raise TargetUnreachableError("", "sin IP de objetivo — usa: admapper scan --ip-dc <DC_IP>")

    last_detail = ""
    for ip in candidates:
        ok, detail = probe_host_reachable(ip, timeout=timeout)
        if ok:
            return ip
        last_detail = detail

    raise TargetUnreachableError(candidates[0], last_detail)


def format_unreachable_message(exc: TargetUnreachableError) -> str:
    host = exc.host or "objetivo"
    detail = exc.detail or "sin ruta"
    lower = detail.lower()
    if "113" in detail or "no route to host" in lower:
        hint = "La máquina está apagada o no hay VPN/ruta al lab."
    elif "timed out" in lower or "110" in detail:
        hint = "Timeout — comprueba VPN y que la IP del lab sigue activa."
    elif "connection refused" in lower or "111" in detail:
        hint = "Hay ruta pero los servicios AD no responden aún — espera a que arranque la VM."
    elif not exc.host:
        hint = "Registra el DC: admapper scan --ip-dc <IP> o admapper run -H <IP> ..."
    else:
        hint = "Enciende la VM HTB, conecta VPN y reintenta."
    return (
        f"Target {host} no alcanzable ({detail}). {hint} "
        f"Cuando esté online: admapper brief -w <workspace> --auto"
    )
