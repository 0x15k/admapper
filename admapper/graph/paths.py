from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from admapper.graph.build import node_display_name
from admapper.graph.catalog import edge_meta, is_high_value_group


@dataclass
class PathStep:
    source: str
    target: str
    edge_type: str
    narrative: str
    mitre_id: str | None = None
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type,
            "narrative": self.narrative,
            "mitre_id": self.mitre_id,
            "severity": self.severity,
        }


@dataclass
class AttackPath:
    id: str
    source: str
    target: str
    length: int
    impact: str
    steps: list[PathStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "source_label": self.source,
            "target_label": self.target,
            "length": self.length,
            "impact": self.impact,
            "steps": [s.to_dict() for s in self.steps],
        }


def _owned_sources(nodes: list[dict[str, Any]]) -> list[str]:
    return [str(n["id"]) for n in nodes if n.get("owned")]


def _target_groups(nodes: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for node in nodes:
        if node.get("type") != "group":
            continue
        name = str(node.get("name", ""))
        if node.get("high_value") or is_high_value_group(name):
            targets.append(str(node["id"]))
    return targets


def _build_adjacency(edges: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    adj: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        src = str(edge.get("source", ""))
        adj.setdefault(src, []).append(edge)
    return adj


def find_attack_paths(
    graph: dict[str, Any],
    *,
    max_depth: int = 8,
    max_paths: int = 25,
) -> list[AttackPath]:
    """Phase 9.3 — BFS from owned nodes to high-value groups."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    nodes_by_id = {str(n["id"]): n for n in nodes}
    sources = _owned_sources(nodes)
    targets = set(_target_groups(nodes))
    if not sources or not targets:
        return []

    adj = _build_adjacency(edges)
    found: list[AttackPath] = []
    seen_paths: set[tuple[str, ...]] = set()

    for start in sources:
        queue: deque[tuple[str, list[dict[str, Any]]]] = deque([(start, [])])
        visited_depth: dict[str, int] = {start: 0}

        while queue and len(found) < max_paths:
            node_id, path_edges = queue.popleft()
            depth = len(path_edges)
            if depth > max_depth:
                continue

            if node_id in targets and node_id != start and path_edges:
                sig = tuple(e["id"] for e in path_edges)
                if sig not in seen_paths:
                    seen_paths.add(sig)
                    found.append(
                        _build_attack_path(
                            path_id=f"path-{len(found) + 1:03d}",
                            path_edges=path_edges,
                            nodes_by_id=nodes_by_id,
                            start=start,
                            end=node_id,
                        )
                    )
                continue

            for edge in adj.get(node_id, []):
                nxt = str(edge.get("target", ""))
                if not nxt or nxt == node_id:
                    continue
                new_depth = depth + 1
                if visited_depth.get(nxt, 999) <= new_depth:
                    continue
                visited_depth[nxt] = new_depth
                queue.append((nxt, [*path_edges, edge]))

    found.sort(key=lambda p: (p.length, p.target))
    return found


def _build_attack_path(
    *,
    path_id: str,
    path_edges: list[dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
    start: str,
    end: str,
) -> AttackPath:
    steps: list[PathStep] = []
    max_severity = "info"
    severity_rank = {"info": 0, "medium": 1, "high": 2, "critical": 3}

    for edge in path_edges:
        etype = str(edge.get("type", "member_of"))
        meta = edge_meta(etype)
        src_label = node_display_name(nodes_by_id, str(edge.get("source", "")))
        tgt_label = node_display_name(nodes_by_id, str(edge.get("target", "")))
        targets = edge.get("targets")
        narrative = meta.narrative.format(
            source=src_label,
            target=tgt_label,
            targets=", ".join(str(t) for t in (targets or [])),
            edge_type=etype,
        )
        steps.append(
            PathStep(
                source=str(edge.get("source", "")),
                target=str(edge.get("target", "")),
                edge_type=etype,
                narrative=narrative,
                mitre_id=meta.mitre_id,
                severity=meta.severity,
            )
        )
        if severity_rank.get(meta.severity, 0) > severity_rank.get(max_severity, 0):
            max_severity = meta.severity

    target_name = str(nodes_by_id.get(end, {}).get("name", "")).lower()
    impact = "critical" if target_name == "domain admins" else max_severity

    return AttackPath(
        id=path_id,
        source=start,
        target=end,
        length=len(steps),
        impact=impact,
        steps=steps,
    )
