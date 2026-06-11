from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class OperationMode(StrEnum):
    AUTO = "auto"
    SEMI = "semi"
    MANUAL = "manual"


@dataclass
class WorkspaceState:
    """Persisted engagement state for one workspace."""

    name: str
    domain: str | None = None
    hosts: str | None = None
    mode: OperationMode = OperationMode.SEMI
    owned_users: list[str] = field(default_factory=list)
    pivot_user: str | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "domain": self.domain,
            "hosts": self.hosts,
            "mode": self.mode.value,
            "owned_users": list(self.owned_users),
            "pivot_user": self.pivot_user,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkspaceState:
        mode_raw = str(data.get("mode", OperationMode.SEMI.value))
        try:
            mode = OperationMode(mode_raw)
        except ValueError:
            mode = OperationMode.SEMI
        return cls(
            name=str(data.get("name", "")),
            domain=data.get("domain"),
            hosts=data.get("hosts"),
            mode=mode,
            owned_users=list(data.get("owned_users") or []),
            pivot_user=data.get("pivot_user"),
            notes=str(data.get("notes") or ""),
        )
