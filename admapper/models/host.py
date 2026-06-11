from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HostRecord:
    """Discovered host with open AD-related services."""

    address: str
    hostname: str | None = None
    open_ports: list[int] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    is_domain_controller: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "hostname": self.hostname,
            "open_ports": list(self.open_ports),
            "roles": list(self.roles),
            "is_domain_controller": self.is_domain_controller,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HostRecord:
        return cls(
            address=str(data.get("address", "")),
            hostname=data.get("hostname"),
            open_ports=[int(p) for p in data.get("open_ports") or []],
            roles=list(data.get("roles") or []),
            is_domain_controller=bool(data.get("is_domain_controller")),
        )
