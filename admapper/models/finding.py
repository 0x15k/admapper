from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import uuid4


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """One security-relevant observation from a scan phase."""

    key: str
    title: str
    severity: FindingSeverity
    source: str
    detail: str = ""
    mitre_id: str | None = None
    host: str | None = None
    id: str = field(default_factory=lambda: uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "title": self.title,
            "severity": self.severity.value,
            "source": self.source,
            "detail": self.detail,
            "mitre_id": self.mitre_id,
            "host": self.host,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        severity_raw = str(data.get("severity", FindingSeverity.INFO.value))
        try:
            severity = FindingSeverity(severity_raw)
        except ValueError:
            severity = FindingSeverity.INFO
        return cls(
            id=str(data.get("id") or uuid4().hex[:12]),
            key=str(data.get("key", "")),
            title=str(data.get("title", "")),
            severity=severity,
            source=str(data.get("source", "")),
            detail=str(data.get("detail") or ""),
            mitre_id=data.get("mitre_id"),
            host=data.get("host"),
        )
