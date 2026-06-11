from __future__ import annotations

import re

from admapper.core.hosts import HostsStore
from admapper.core.users import UsersStore
from admapper.models.mssql_op import MssqlInstance

if True:
    from admapper.core.session import Session

_MSSQL_SPN_RE = re.compile(r"^MSSQLSvc/([^:/]+)", re.IGNORECASE)


def discover_mssql_instances(session: Session) -> list[MssqlInstance]:
    """Phase 15.1 — find MSSQL targets from hosts, SPNs, and computers."""
    if session.workspace is None:
        return []

    ws_name = session.workspace.name
    seen: set[tuple[str, int]] = set()
    instances: list[MssqlInstance] = []

    def add(host: str, *, port: int = 1433, instance: str | None = None, spn: str | None = None) -> None:
        key = (host.lower(), port)
        if key in seen:
            return
        seen.add(key)
        instances.append(
            MssqlInstance(host=host, port=port, instance=instance, spn=spn)
        )

    for host in HostsStore(session.workspaces, ws_name).list():
        if 1433 in (host.open_ports or []):
            add(host.address, port=1433)

    users_store = UsersStore(session.workspaces, ws_name)
    for user in users_store.list():
        for spn in user.spns or []:
            match = _MSSQL_SPN_RE.match(spn)
            if not match:
                continue
            target = match.group(1).split(":")[0]
            add(target, spn=spn)

    return instances
