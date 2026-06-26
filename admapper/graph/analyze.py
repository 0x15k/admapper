from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.graph.build import enrich_graph_from_inventory, node_display_name
from admapper.graph.opportunity_paths import build_opportunity_paths
from admapper.graph.paths import AttackPath, find_attack_paths
from admapper.graph.quick_wins import QuickWin, collect_quick_wins
from admapper.guides.render import print_manual_guide
from admapper.stores.graph import GraphStore
from admapper.support.output import print_info, print_success, print_table, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class GraphAnalysisResult:
    paths: list[AttackPath] = field(default_factory=list)
    quick_wins: list[QuickWin] = field(default_factory=list)
    graph_path: str | None = None
    paths_path: str | None = None


def _load_inventory(workspace_path) -> dict[str, Any] | None:
    inv_file = workspace_path / "auth_inventory.json"
    if not inv_file.is_file():
        return None
    return json.loads(inv_file.read_text(encoding="utf-8"))


def _path_to_dict(path: AttackPath, nodes_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": path.id,
        "source": path.source,
        "target": path.target,
        "source_label": node_display_name(nodes_by_id, path.source),
        "target_label": node_display_name(nodes_by_id, path.target),
        "length": path.length,
        "impact": path.impact,
        "steps": [s.to_dict() for s in path.steps],
    }


def run_graph_analysis(session: Session) -> GraphAnalysisResult:
    """Phase 9 — rebuild graph edges, compute attack paths, collect quick wins."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before paths")

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)
    graph_store = GraphStore(session.workspaces, ws_name)

    print_info("Phase 9 — attack graph analysis")
    graph = graph_store.load()
    inventory = _load_inventory(ws_path)
    if inventory is None:
        print_warning("no auth_inventory.json — run start_auth for richer paths")
    else:
        graph = enrich_graph_from_inventory(
            graph,
            inventory,
            domain=domain,
            owned_users=session.workspace.owned_users,
        )
        graph_store.save(graph)
        print_success(f"graph enriched → {graph_store.path.name}")

    nodes_by_id = {str(n["id"]): n for n in graph.get("nodes", [])}
    paths = find_attack_paths(graph)
    opp_paths = build_opportunity_paths(graph, ws_path, domain=domain, path_offset=len(paths))
    paths = paths + [p.to_attack_path() for p in opp_paths]
    quick_wins = collect_quick_wins(session.workspaces, ws_name)

    paths_file = ws_path / "paths.json"
    payload = {
        "domain": domain,
        "path_count": len(paths),
        "paths": [_path_to_dict(p, nodes_by_id) for p in paths],
        "quick_wins": [w.to_dict() for w in quick_wins],
    }
    paths_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = GraphAnalysisResult(
        paths=paths,
        quick_wins=quick_wins,
        graph_path=str(graph_store.path),
        paths_path=str(paths_file),
    )

    if paths:
        rows = [
            [
                p.id,
                node_display_name(nodes_by_id, p.source),
                node_display_name(nodes_by_id, p.target),
                str(p.length),
                p.impact,
            ]
            for p in paths[:15]
        ]
        print_table("Attack paths", ["id", "from", "to", "hops", "impact"], rows)
    else:
        print_warning("no paths to high-value groups — mark owned users and run start_auth")

    if quick_wins:
        qw_rows = [[w.title, w.severity, w.detail[:60]] for w in quick_wins[:10]]
        print_table("Quick wins", ["title", "severity", "detail"], qw_rows)

    print_success("paths saved → paths.json")
    print_manual_guide("attack_paths", session=session)
    return result


def get_path_detail(session: Session, path_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    paths_file = session.workspaces.path_for(session.workspace.name) / "paths.json"
    if not paths_file.is_file():
        return None
    data = json.loads(paths_file.read_text(encoding="utf-8"))
    for item in data.get("paths", []):
        if str(item.get("id")) == path_id:
            return item
    return None
