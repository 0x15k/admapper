from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportItem:
    category: str
    title: str
    severity: str
    source: str
    detail: str = ""
    item_id: str | None = None
    mitre_id: str | None = None
    host: str | None = None
    technique: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "source": self.source,
            "detail": self.detail,
        }
        if self.item_id:
            payload["id"] = self.item_id
        if self.mitre_id:
            payload["mitre_id"] = self.mitre_id
        if self.host:
            payload["host"] = self.host
        if self.technique:
            payload["technique"] = self.technique
        if self.extra:
            payload["extra"] = dict(self.extra)
        return payload
