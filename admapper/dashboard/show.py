from __future__ import annotations

from pathlib import Path
from typing import Any

from admapper.escalate.edges import collect_edges_from_pivot, sort_edges
from admapper.report.engagement import _load_json
from admapper.support.output import print_success, print_warning


def _node_label(node: dict[str, Any], *, owned_mark: bool = False) -> str:
    if node.get("type") == "user":
        name = str(node.get("username", ""))
        if owned_mark and node.get("owned"):
            return f"★ {name}"
        return name
    return str(node.get("name") or node.get("username") or node.get("id", ""))


def _edge_label(edge: dict[str, Any]) -> str:
    etype = str(edge.get("type", "edge"))
    if edge.get("technique"):
        return str(edge["technique"])
    if edge.get("right"):
        return str(edge["right"])
    return etype.replace("_", " ")


def _outbound_edges(
    graph: dict[str, Any],
    *,
    node_id: str,
    owned: set[str],
) -> list[tuple[str, str, str]]:
    """Return (target_label, edge_type, status) from graph edges."""
    nodes_by_id = {str(n["id"]): n for n in graph.get("nodes", []) if n.get("id")}
    rows: list[tuple[str, str, str]] = []
    for edge in graph.get("edges", []):
        if str(edge.get("source")) != node_id:
            continue
        target_id = str(edge.get("target", ""))
        target = nodes_by_id.get(target_id, {})
        label = (
            _node_label(target, owned_mark=False)
            if target
            else target_id.split(":")[-1].split("@")[0]
        )
        etype = _edge_label(edge)
        tgt_user = str(target.get("username", label)).lower()
        status = "owned" if tgt_user in owned or target.get("owned") else "edge"
        rows.append((label, etype, status))
    return rows


def build_graph_view(
    ws_path: Path,
    *,
    domain: str,
    pivot_user: str | None = None,
    owned_users: list[str] | None = None,
    max_depth: int = 4,
) -> str:
    """ASCII attack graph from owned pivot — graph.json + escalate + ACL edges."""
    owned = {u.lower() for u in (owned_users or [])}
    pivot = pivot_user or (list(owned_users or [])[-1] if owned_users else "")
    graph = _load_json(ws_path / "graph.json") or {"nodes": [], "edges": []}
    acl = _load_json(ws_path / "acl_findings.json") or {}
    paths = _load_json(ws_path / "paths.json") or {}

    lines = [
        "═" * 48,
        "  ATTACK GRAPH  (admapper — without BloodHound CE)",
        "═" * 48,
        f"  pivot : {pivot or '(none)'}",
        f"  owned : {', '.join(owned_users or []) or '(none)'}",
        "",
    ]

    from admapper.creds.common import collect_gained_hashes, format_evil_winrm_pth

    hashes = collect_gained_hashes(ws_path)
    if hashes:
        account, nthash = hashes[-1]
        host, winrm_cmd = format_evil_winrm_pth(
            account=account,
            nthash=nthash,
            domain=domain,
            ws_path=ws_path,
        )
        lines.extend(
            [
                "  NEXT STEP  [ready]",
                f"  {account} ──WinRM──► {host}",
                f"  Command   : {winrm_cmd}",
                "",
            ]
        )

    if pivot:
        edges = collect_edges_from_pivot(
            pivot_user=pivot,
            owned_users=list(owned_users or []),
            ws_path=ws_path,
            domain=domain,
        )
        ready = [
            e
            for e in sort_edges(edges)
            if e.ready and not e.target_owned and e.technique != "member_of"
        ]
        if ready:
            lines.append("  FROM PIVOT (1-hop — BloodHound style)")
            for edge in ready[:8]:
                mark = "✓" if edge.ready else "○"
                lines.append(
                    f"  {mark} {pivot} ──{edge.technique}──► {edge.target}  [{edge.severity}]"
                )
            lines.append("")

    pivot_node_id = f"user:{pivot.lower()}@{domain.lower()}" if pivot else ""
    if pivot_node_id:
        hop_edges = _outbound_edges(graph, node_id=pivot_node_id, owned=owned)
        if hop_edges:
            lines.append("  GRAPH EDGES (member_of / ACL from graph.json)")
            for label, etype, status in hop_edges[:12]:
                lines.append(f"    {pivot} ──{etype}──► {label}  ({status})")
            lines.append("")

    for finding in acl.get("findings") or []:
        principal = str(finding.get("principal", "")).lower()
        if principal and principal != pivot.lower():
            continue
        lines.append("  ACL ABUSE")
        lines.append(
            f"    {finding.get('principal')} ──{finding.get('right')}──► "
            f"{finding.get('target_name')}  [{finding.get('severity')}]"
        )
        lines.append("")

    path_list = paths.get("paths") or []
    if path_list:
        lines.append("  MULTI-HOP PATHS (paths.json)")
        for path in path_list[:5]:
            steps = path.get("steps") or []
            chain = " → ".join(s.get("narrative", s.get("edge_type", "?"))[:40] for s in steps[:6])
            lines.append(
                f"    {path.get('id')}: {path.get('source_label')} → {path.get('target_label')} "
                f"({path.get('length')} hops)"
            )
            if chain:
                lines.append(f"      {chain}")
        lines.append("")

    nodes = graph.get("nodes", [])
    owned_nodes = [n for n in nodes if n.get("owned")]
    if owned_nodes:
        lines.append("  OWNED NODES")
        for node in owned_nodes[:15]:
            lines.append(f"    ★ {_node_label(node, owned_mark=False)}")
        lines.append("")

    if len(lines) <= 8:
        lines.append("  (empty graph — run start_auth + acls + paths)")
        lines.append("")

    lines.append("═" * 48)
    return "\n".join(lines)


def print_attack_graph(
    ws_path: Path,
    *,
    domain: str | None,
    pivot_user: str | None = None,
    owned_users: list[str] | None = None,
) -> None:
    domain = domain or "(no domain)"
    text = build_graph_view(
        ws_path,
        domain=domain,
        pivot_user=pivot_user,
        owned_users=owned_users,
    )
    print_success("ADMapper — Attack Graph")
    for line in text.splitlines():
        if line.strip().startswith("✓") or "──" in line or "NEXT STEP" in line:
            print_warning(line)
        else:
            print(line)
