from __future__ import annotations

from typing import TYPE_CHECKING, Any

from admapper.models.cve_finding import CveTarget
from admapper.stores.hosts import HostsStore

if TYPE_CHECKING:
    from admapper.support.session import Session


def _host_port_map(session: Session) -> dict[str, list[int]]:
    if session.workspace is None:
        return {}
    mapping: dict[str, list[int]] = {}
    for host in HostsStore(session.workspaces, session.workspace.name).list():
        keys = [host.address.lower()]
        if host.hostname:
            keys.append(host.hostname.lower())
        for key in keys:
            mapping[key] = list(host.open_ports or [])
    return mapping


def discover_cve_targets(
    session: Session,
    inventory: dict[str, Any] | None,
) -> list[CveTarget]:
    """Phase 16.5 — build target list from auth inventory + hosts."""
    if session.workspace is None:
        return []

    port_map = _host_port_map(session)
    dc_hosts = {
        h.address.lower()
        for h in HostsStore(session.workspaces, session.workspace.name).list()
        if h.is_domain_controller and h.address
    }
    dc_names = {
        (h.hostname or "").lower()
        for h in HostsStore(session.workspaces, session.workspace.name).list()
        if h.is_domain_controller and h.hostname
    }

    targets: list[CveTarget] = []
    seen: set[str] = set()

    for computer in (inventory or {}).get("computers") or []:
        name = str(computer.get("name") or "")
        dns = str(computer.get("dns_host") or "")
        host = dns or name
        if not host:
            continue
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)

        ports = port_map.get(key, port_map.get(name.lower(), []))
        is_dc = (
            key in dc_hosts
            or name.lower() in dc_names
            or name.upper().endswith("DC")
            or "domain controller" in str(computer.get("operating_system") or "").lower()
        )
        targets.append(
            CveTarget(
                host=host,
                computer_name=name or None,
                operating_system=computer.get("operating_system"),
                is_domain_controller=is_dc,
                open_ports=ports,
            )
        )

    for host_record in HostsStore(session.workspaces, session.workspace.name).list():
        host = host_record.hostname or host_record.address
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)
        targets.append(
            CveTarget(
                host=host,
                computer_name=host_record.hostname,
                operating_system=None,
                is_domain_controller=host_record.is_domain_controller,
                open_ports=list(host_record.open_ports or []),
            )
        )

    return targets
