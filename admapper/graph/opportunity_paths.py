from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admapper.graph.paths import AttackPath, PathStep


@dataclass
class OpportunityPath:
    id: str
    source: str
    target: str
    impact: str
    technique: str
    summary: str
    steps: list[PathStep] = field(default_factory=list)
    mitre_id: str | None = None

    def to_attack_path(self) -> AttackPath:
        return AttackPath(
            id=self.id,
            source=self.source,
            target=self.target,
            length=len(self.steps),
            impact=self.impact,
            steps=self.steps,
        )


def _owned_user_ids(graph: dict[str, Any], domain: str) -> list[str]:
    return [
        str(n["id"])
        for n in graph.get("nodes", [])
        if n.get("type") == "user" and n.get("owned")
    ]


def _node_id_for_principal(graph: dict[str, Any], name: str, domain: str) -> str | None:
    key = name.strip().lower()
    for n in graph.get("nodes", []):
        ntype = n.get("type")
        if ntype == "user" and (
            str(n.get("username", "")).lower() == key
            or str(n.get("name", "")).lower() == key
        ):
            return str(n["id"])
        if ntype in {"computer", "group"} and str(n.get("name", "")).lower() == key:
            return str(n["id"])
    return None


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _add_edges_for_path(
    graph: dict[str, Any],
    source_id: str,
    target_id: str,
    edge_type: str,
    *,
    narrative: str,
    mitre_id: str | None = None,
    severity: str = "medium",
    targets: list[str] | None = None,
) -> None:
    """Ensure graph edges contain the opportunity edge so visualisers can highlight it."""
    edge_id = f"{source_id}->{edge_type}->{target_id}"
    edges = graph.setdefault("edges", [])
    if any(e.get("id") == edge_id for e in edges):
        return
    edge: dict[str, Any] = {
        "id": edge_id,
        "source": source_id,
        "target": target_id,
        "type": edge_type,
        "narrative": narrative,
        "mitre_id": mitre_id,
        "severity": severity,
        "opportunity": True,
    }
    if targets is not None:
        edge["targets"] = targets
    edges.append(edge)


def build_opportunity_paths(
    graph: dict[str, Any],
    ws_path: Path,
    *,
    domain: str,
    path_offset: int = 0,
) -> list[OpportunityPath]:
    """Build attack paths from discovered opportunities when no ACL/group path exists."""
    paths: list[OpportunityPath] = []
    owned_sources = _owned_user_ids(graph, domain)
    if not owned_sources:
        return paths

    owned_source = owned_sources[0]
    idx = path_offset

    inv = _load_json(ws_path / "auth_inventory.json") or {}
    for user in inv.get("users", []):
        if not user.get("kerberoastable"):
            continue
        target_name = str(user.get("username", ""))
        target_id = _node_id_for_principal(graph, target_name, domain)
        if not target_id:
            continue
        idx += 1
        _add_edges_for_path(
            graph,
            owned_source,
            target_id,
            "kerberoastable",
            narrative=f"Owned principal can request a crackable TGS for {target_name}.",
            mitre_id="T1558.003",
            severity="medium",
            targets=user.get("spns") or [],
        )
        paths.append(
            OpportunityPath(
                id=f"path-{idx:03d}",
                source=owned_source,
                target=target_id,
                impact="medium",
                technique="kerberoastable",
                summary=f"Kerberoast {target_name} and crack the TGS offline",
                steps=[
                    PathStep(
                        source=owned_source,
                        target=target_id,
                        edge_type="kerberoastable",
                        narrative=f"Request a crackable TGS for {target_name} ({', '.join(user.get('spns') or [])})",
                        mitre_id="T1558.003",
                        severity="medium",
                    )
                ],
                mitre_id="T1558.003",
            )
        )

    adcs = _load_json(ws_path / "adcs_findings.json") or {}
    for finding in adcs.get("findings", []):
        esc = str(finding.get("esc", ""))
        if esc not in {"esc11", "golden_cert"}:
            continue
        ca_name = str(finding.get("ca_name", "CA"))
        target_id = f"adcs:{ca_name.lower()}"
        if not any(n.get("id") == target_id for n in graph.get("nodes", [])):
            graph.setdefault("nodes", []).append(
                {
                    "id": target_id,
                    "type": "adcs",
                    "name": ca_name,
                    "domain": domain.lower(),
                    "owned": False,
                }
            )
        idx += 1
        impact = "critical" if esc == "golden_cert" else "high"
        _add_edges_for_path(
            graph,
            owned_source,
            target_id,
            esc,
            narrative=str(finding.get("summary", f"AD CS {esc}")),
            mitre_id="T1649",
            severity=impact,
        )
        paths.append(
            OpportunityPath(
                id=f"path-{idx:03d}",
                source=owned_source,
                target=target_id,
                impact=impact,
                technique=esc,
                summary=str(finding.get("title", f"AD CS {esc}")),
                steps=[
                    PathStep(
                        source=owned_source,
                        target=target_id,
                        edge_type=esc,
                        narrative=str(finding.get("summary", "")),
                        mitre_id="T1649",
                        severity=impact,
                    )
                ],
                mitre_id="T1649",
            )
        )

    coerce = _load_json(ws_path / "coerce_ops.json") or {}
    for opp in coerce.get("opportunities", []):
        listener = str(opp.get("listener_host", "DC"))
        target_id = _node_id_for_principal(graph, listener, domain)
        if not target_id:
            target_id = f"computer:{listener.lower()}.{domain.lower()}"
            graph.setdefault("nodes", []).append(
                {
                    "id": target_id,
                    "type": "computer",
                    "name": listener,
                    "domain": domain.lower(),
                    "owned": False,
                }
            )
        idx += 1
        tech = str(opp.get("technique", "coerce"))
        _add_edges_for_path(
            graph,
            owned_source,
            target_id,
            tech,
            narrative=str(opp.get("summary", f"{tech} coercion")),
            mitre_id="T1187",
            severity="high",
        )
        paths.append(
            OpportunityPath(
                id=f"path-{idx:03d}",
                source=owned_source,
                target=target_id,
                impact="high",
                technique=tech,
                summary=str(opp.get("title", f"Coerce {listener}")),
                steps=[
                    PathStep(
                        source=owned_source,
                        target=target_id,
                        edge_type=tech,
                        narrative=str(opp.get("summary", "")),
                        mitre_id="T1187",
                        severity="high",
                    )
                ],
                mitre_id="T1187",
            )
        )

    return paths
