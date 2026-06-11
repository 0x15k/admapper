from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EscalationEdge:
    """One outbound hop from the current pivot user (BloodHound-style edge)."""

    technique: str
    module: str
    title: str
    severity: str
    summary: str
    target: str = ""
    op_id: str = ""
    ready: bool = True
    target_owned: bool = False
    manual_commands: list[str] = field(default_factory=list)
    mitre_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "module": self.module,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "target": self.target,
            "op_id": self.op_id,
            "ready": self.ready,
            "target_owned": self.target_owned,
            "manual_commands": list(self.manual_commands),
            "mitre_id": self.mitre_id,
        }


@dataclass
class EscalationState:
    pivot_user: str
    owned_users: list[str]
    edges: list[EscalationEdge] = field(default_factory=list)
    next_edge: EscalationEdge | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pivot_user": self.pivot_user,
            "owned_users": list(self.owned_users),
            "edge_count": len(self.edges),
            "edges": [e.to_dict() for e in self.edges],
            "next": self.next_edge.to_dict() if self.next_edge else None,
            "history": list(self.history),
        }
