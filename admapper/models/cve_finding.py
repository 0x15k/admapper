from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CveTarget:
    host: str
    computer_name: str | None = None
    operating_system: str | None = None
    is_domain_controller: bool = False
    open_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "computer_name": self.computer_name,
            "operating_system": self.operating_system,
            "is_domain_controller": self.is_domain_controller,
            "open_ports": list(self.open_ports),
        }


@dataclass
class CveFinding:
    technique: str
    title: str
    severity: str
    mitre_id: str
    cve_ids: list[str]
    summary: str
    target_host: str
    detail: str = ""
    confidence: str = "medium"
    exploitable: bool = False
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "technique": self.technique,
            "title": self.title,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "cve_ids": list(self.cve_ids),
            "summary": self.summary,
            "target_host": self.target_host,
            "detail": self.detail,
            "confidence": self.confidence,
            "exploitable": self.exploitable,
            "manual_commands": list(self.manual_commands),
        }
