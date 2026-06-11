from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WsusOpportunity:
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
    prerequisites_met: bool = True
    prerequisites: list[dict[str, Any]] = field(default_factory=list)

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
            "prerequisites_met": self.prerequisites_met,
            "prerequisites": list(self.prerequisites),
        }
