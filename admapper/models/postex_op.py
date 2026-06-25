from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PostexOpportunity:
    technique: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    target_host: str | None = None
    context: str | None = None
    detail: str = ""
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""
    dcsync_attempted: bool = False
    dcsync_failed: bool = False

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
            "dcsync_attempted": self.dcsync_attempted,
            "dcsync_failed": self.dcsync_failed,
            "manual_commands": list(self.manual_commands),
        }
