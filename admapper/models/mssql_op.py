from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MssqlInstance:
    host: str
    port: int = 1433
    instance: str | None = None
    spn: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "instance": self.instance,
            "spn": self.spn,
        }


@dataclass
class MssqlOpportunity:
    technique: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    target_host: str
    detail: str = ""
    context: str | None = None
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "technique": self.technique,
            "title": self.title,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "summary": self.summary,
            "target_host": self.target_host,
            "context": self.context,
            "detail": self.detail,
            "manual_commands": list(self.manual_commands),
        }
