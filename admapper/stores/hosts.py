from __future__ import annotations

import json
from pathlib import Path

from admapper.models.host import HostRecord
from admapper.support.workspace import WorkspaceManager


class HostsStore:
    """JSON-backed host inventory for the active workspace."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    @property
    def _path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "hosts.json"

    def list(self) -> list[HostRecord]:
        if not self._path.is_file():
            return []
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return [HostRecord.from_dict(item) for item in data.get("hosts", [])]

    def save_all(self, hosts: list[HostRecord]) -> Path:
        workspace_dir = self._workspace.path_for(self._workspace_name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        payload = {"hosts": [h.to_dict() for h in hosts]}
        self._path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self._path

    def merge(self, new_hosts: list[HostRecord]) -> list[HostRecord]:
        existing = {h.address: h for h in self.list()}
        for host in new_hosts:
            if host.address in existing:
                prior = existing[host.address]
                merged_ports = sorted(set(prior.open_ports) | set(host.open_ports))
                merged_roles = sorted(set(prior.roles) | set(host.roles))
                existing[host.address] = HostRecord(
                    address=host.address,
                    hostname=host.hostname or prior.hostname,
                    open_ports=merged_ports,
                    roles=merged_roles,
                    is_domain_controller=host.is_domain_controller or prior.is_domain_controller,
                )
            else:
                existing[host.address] = host
        merged = list(existing.values())
        self.save_all(merged)
        return merged
