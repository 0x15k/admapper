from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CoerceOpportunity:
    technique: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    source_host: str | None = None
    listener_host: str | None = None
    relay_target: str | None = None
    detail: str = ""
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""
    requires_external_listener: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "technique": self.technique,
            "title": self.title,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "summary": self.summary,
            "source_host": self.source_host,
            "listener_host": self.listener_host,
            "relay_target": self.relay_target,
            "detail": self.detail,
            "manual_commands": list(self.manual_commands),
        }
