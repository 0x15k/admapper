from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KerberosOpportunity:
    technique: str
    title: str
    severity: str
    mitre_id: str
    source_object: str
    source_type: str
    summary: str
    detail: str = ""
    target: str | None = None
    targets: list[str] = field(default_factory=list)
    owned_relevant: bool = False
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "technique": self.technique,
            "title": self.title,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "source_object": self.source_object,
            "source_type": self.source_type,
            "target": self.target,
            "targets": list(self.targets),
            "summary": self.summary,
            "detail": self.detail,
            "owned_relevant": self.owned_relevant,
            "manual_commands": list(self.manual_commands),
        }
