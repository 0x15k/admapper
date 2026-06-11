from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChainStep:
    order: int
    technique: str
    module: str
    op_id: str | None
    title: str
    ready: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "technique": self.technique,
            "module": self.module,
            "op_id": self.op_id,
            "title": self.title,
            "ready": self.ready,
            "detail": self.detail,
        }


@dataclass
class ChainOpportunity:
    chain_id: str
    title: str
    severity: str
    summary: str
    target_host: str
    steps: list[ChainStep] = field(default_factory=list)
    ready: bool = False
    context: str | None = None
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "target_host": self.target_host,
            "context": self.context,
            "ready": self.ready,
            "steps": [s.to_dict() for s in self.steps],
            "manual_commands": list(self.manual_commands),
        }
