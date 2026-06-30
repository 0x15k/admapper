from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admapper.graph.catalog import edge_meta, is_high_value_group


def _node_label(node: dict[str, Any]) -> str:
    ntype = node.get("type", "object")
    if ntype == "user":
        return str(node.get("username", node.get("id", "")))
    if ntype in {"group", "computer", "domain"}:
        return str(node.get("name", node.get("id", "")))
    return str(node.get("id", ""))


def _dn_index(nodes: list[dict[str, Any]]) -> dict[str, str]:
    by_dn: dict[str, str] = {}
    for node in nodes:
        dn = node.get("dn")
        if dn:
            by_dn[str(dn).lower()] = str(node["id"])
    return by_dn


def _ensure_user_nodes_from_inventory(
    nodes: list[dict[str, Any]],
    inventory: dict[str, Any],
    domain: str,
    owned_users: set[str],
) -> None:
    existing = {n.get("id") for n in nodes}
    for user in inventory.get("users", []):
        username = str(user.get("username", ""))
        if not username:
            continue
        node_id = f"user:{username.lower()}@{domain.lower()}"
        if node_id in existing:
            for node in nodes:
                if node.get("id") == node_id:
                    node["dn"] = user.get("dn") or node.get("dn")
                    if username.lower() in owned_users:
                        node["owned"] = True
                        node["labels"] = list(set([*(node.get("labels") or []), "owned"]))
            continue
        nodes.append(
            {
                "id": node_id,
                "type": "user",
                "username": username,
                "domain": domain.lower(),
                "dn": user.get("dn"),
                "owned": username.lower() in owned_users,
                "labels": ["owned"] if username.lower() in owned_users else [],
                "kerberoastable": user.get("kerberoastable"),
                "asrep_roastable": user.get("asrep_roastable"),
                "enabled": user.get("enabled"),
            }
        )
        existing.add(node_id)


def enrich_graph_from_inventory(
    graph: dict[str, Any],
    inventory: dict[str, Any],
    *,
    domain: str,
    owned_users: list[str] | None = None,
) -> dict[str, Any]:
    """Phase 9.1 — add member_of edges and high-value flags from auth_inventory."""
    nodes: list[dict[str, Any]] = list(graph.get("nodes", []))
    edges: list[dict[str, Any]] = list(graph.get("edges", []))
    owned_set = {u.lower() for u in (owned_users or [])}
    edge_ids = {e.get("id") for e in edges}

    _ensure_user_nodes_from_inventory(nodes, inventory, domain, owned_set)

    for group in inventory.get("groups", []):
        name = str(group.get("name", ""))
        if not name:
            continue
        node_id = f"group:{name.lower()}@{domain.lower()}"
        if not any(n.get("id") == node_id for n in nodes):
            nodes.append(
                {
                    "id": node_id,
                    "type": "group",
                    "name": name,
                    "domain": domain.lower(),
                    "dn": group.get("dn"),
                    "owned": False,
                    "high_value": is_high_value_group(name),
                }
            )
        else:
            for node in nodes:
                if node.get("id") == node_id:
                    node["dn"] = group.get("dn") or node.get("dn")
                    node["high_value"] = is_high_value_group(name)

    dn_map = _dn_index(nodes)

    for group in inventory.get("groups", []):
        name = str(group.get("name", ""))
        group_id = f"group:{name.lower()}@{domain.lower()}"
        for member_dn in group.get("members") or []:
            member_id = dn_map.get(str(member_dn).lower())
            if not member_id:
                continue
            edge_id = f"{member_id}->member_of->{group_id}"
            if edge_id in edge_ids:
                continue
            edges.append(
                {
                    "id": edge_id,
                    "source": member_id,
                    "target": group_id,
                    "type": "member_of",
                }
            )
            edge_ids.add(edge_id)

    for user in inventory.get("users", []):
        username = str(user.get("username", ""))
        if not username:
            continue
        user_id = f"user:{username.lower()}@{domain.lower()}"
        for group_dn in user.get("member_of") or []:
            group_id = dn_map.get(str(group_dn).lower())
            if not group_id:
                continue
            edge_id = f"{user_id}->member_of->{group_id}"
            if edge_id in edge_ids:
                continue
            edges.append(
                {
                    "id": edge_id,
                    "source": user_id,
                    "target": group_id,
                    "type": "member_of",
                }
            )
            edge_ids.add(edge_id)

    for delegation in inventory.get("delegations", []):
        obj_name = str(delegation.get("object_name", ""))
        dtype = str(delegation.get("delegation_type", ""))
        obj_type = str(delegation.get("object_type", "user"))
        if obj_type == "computer":
            source_id = f"computer:{obj_name.lower()}.{domain.lower()}"
        else:
            source_id = f"user:{obj_name.lower()}@{domain.lower()}"
        if not any(n.get("id") == source_id for n in nodes):
            continue
        if dtype == "unconstrained":
            edge_id = f"{source_id}->unconstrained_delegation->{source_id}"
            if edge_id not in edge_ids:
                edges.append(
                    {
                        "id": edge_id,
                        "source": source_id,
                        "target": source_id,
                        "type": "unconstrained_delegation",
                    }
                )
                edge_ids.add(edge_id)
        elif dtype in {"constrained", "constrained_pt"}:
            for target in delegation.get("targets") or []:
                target_id = dn_map.get(str(target).lower()) or str(target)
                edge_id = f"{source_id}->constrained_delegation->{target_id}"
                if edge_id not in edge_ids:
                    edges.append(
                        {
                            "id": edge_id,
                            "source": source_id,
                            "target": target_id,
                            "type": (
                                "constrained_pt"
                                if dtype == "constrained_pt"
                                else "constrained_delegation"
                            ),
                            "targets": delegation.get("targets"),
                        }
                    )
                    edge_ids.add(edge_id)
        elif dtype == "rbcd":
            edge_id = f"{source_id}->rbcd->{source_id}"
            if edge_id not in edge_ids:
                edges.append(
                    {
                        "id": edge_id,
                        "source": source_id,
                        "target": source_id,
                        "type": "rbcd",
                    }
                )
                edge_ids.add(edge_id)

    graph["nodes"] = nodes
    graph["edges"] = edges
    graph["meta"] = {
        "domain": domain.lower(),
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
    return graph


@dataclass
class GraphFocusContext:
    """Workspace facts that drive tactical graph filtering."""

    owned_users: list[str] = field(default_factory=list)
    pivot_user: str | None = None
    paths: list[dict[str, Any]] = field(default_factory=list)
    acl_findings: list[dict[str, Any]] = field(default_factory=list)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_focus_context(ws_path: Path) -> GraphFocusContext:
    """Build focus context from workspace artifacts on disk."""
    state = _load_json(ws_path / "state.json")
    paths_data = _load_json(ws_path / "paths.json")
    acl_data = _load_json(ws_path / "acl_findings.json")
    findings = acl_data.get("findings")
    if not isinstance(findings, list):
        findings = acl_data.get("abuse_paths")
    if not isinstance(findings, list):
        findings = []
    return GraphFocusContext(
        owned_users=list(state.get("owned_users") or []),
        pivot_user=state.get("pivot_user"),
        paths=list(paths_data.get("paths") or []),
        acl_findings=[f for f in findings if isinstance(f, dict)],
    )


def _norm_user(value: str) -> str:
    return value.strip().lower().rstrip("$")


def _user_is_owned(username: str, owned: set[str]) -> bool:
    uname = _norm_user(username)
    if not uname:
        return False
    if uname in owned:
        return True
    if f"{uname}$" in owned:
        return True
    return any(_norm_user(o) == uname for o in owned)


def _user_is_pivot(username: str, pivot_n: str) -> bool:
    if not pivot_n:
        return False
    return _norm_user(username) == pivot_n


def _node_username(node: dict[str, Any]) -> str:
    return str(node.get("username") or node.get("name") or "").strip()


def _normalize_edge_type(edge_type: str) -> str:
    return str(edge_type or "").strip().lower().replace("memberof", "member_of")


def _acl_node_id(
    domain: str,
    *,
    target_type: str,
    target_name: str,
) -> str:
    domain_lc = domain.lower()
    ttype = target_type.lower()
    name = target_name.lower()
    if ttype == "user":
        return f"user:{name}@{domain_lc}"
    if ttype == "group":
        return f"group:{name}@{domain_lc}"
    if ttype == "computer":
        base = name.split(".", 1)[0]
        return f"computer:{base}.{domain_lc}"
    if ttype == "domain":
        return f"domain:{domain_lc}"
    return f"object:{name}@{domain_lc}"


def _is_privileged_group_name(name: str) -> bool:
    low = name.strip().lower()
    if is_high_value_group(low):
        return True
    hints = ("admin", "recovery", "protected", "operator", "backup", "schema", "enterprise")
    return any(h in low for h in hints)


def focus_tactical_graph(
    graph: dict[str, Any],
    *,
    domain: str,
    context: GraphFocusContext | None = None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> dict[str, Any]:
    """Reduce graph.json to attack-relevant nodes/edges (owned, paths, ACLs, HV targets).

    Full LDAP inventory is still available in ``auth_inventory.json``. This keeps
    the persisted attack graph readable in the dashboard without client-side filtering.
    """
    nodes: list[dict[str, Any]] = list(graph.get("nodes") or [])
    edges: list[dict[str, Any]] = list(graph.get("edges") or [])
    if not nodes:
        return graph

    ctx = context or GraphFocusContext()
    owned_list = owned_users if owned_users is not None else ctx.owned_users
    pivot = pivot_user if pivot_user is not None else ctx.pivot_user
    owned = {_norm_user(u) for u in owned_list if u}
    pivot_n = _norm_user(pivot) if pivot else ""
    nodes_by_id = {str(n["id"]): n for n in nodes if n.get("id")}

    keep_ids: set[str] = set()

    for node in nodes:
        nid = str(node["id"])
        ntype = str(node.get("type") or "")
        if ntype == "domain":
            keep_ids.add(nid)
            continue
        if ntype == "computer":
            keep_ids.add(nid)
            continue
        if ntype == "group":
            name = str(node.get("name") or "")
            if _is_privileged_group_name(name) or node.get("high_value"):
                keep_ids.add(nid)
            continue
        if ntype == "user":
            uname = _norm_user(_node_username(node))
            if node.get("owned") or _user_is_owned(_node_username(node), owned) or _user_is_pivot(
                _node_username(node), pivot_n
            ):
                keep_ids.add(nid)
                continue
            if node.get("kerberoastable") or node.get("asrep_roastable"):
                keep_ids.add(nid)
                continue
            if node.get("enabled") is False:
                continue

    for path in ctx.paths:
        keep_ids.add(str(path.get("source") or ""))
        keep_ids.add(str(path.get("target") or ""))
        for step in path.get("steps") or []:
            if isinstance(step, dict):
                keep_ids.add(str(step.get("source") or ""))
                keep_ids.add(str(step.get("target") or ""))

    for finding in ctx.acl_findings:
        principal = str(finding.get("principal") or finding.get("owned_user") or "")
        if principal:
            keep_ids.add(_acl_node_id(domain, target_type="user", target_name=principal))
        target_type = str(finding.get("target_type") or "user")
        target_name = str(finding.get("target_name") or finding.get("target") or "")
        if target_name:
            keep_ids.add(_acl_node_id(domain, target_type=target_type, target_name=target_name))

    for edge in edges:
        etype = _normalize_edge_type(str(edge.get("type") or ""))
        severity = str(edge.get("severity") or edge_meta(etype).severity)
        if etype not in {"member_of", "member_of_domain"}:
            keep_ids.add(str(edge.get("source") or ""))
            keep_ids.add(str(edge.get("target") or ""))
        elif severity in {"critical", "high", "medium"}:
            keep_ids.add(str(edge.get("source") or ""))
            keep_ids.add(str(edge.get("target") or ""))

    # Owned / pivot group memberships (drop bulk MemberOf to built-in low-value groups).
    for edge in edges:
        etype = _normalize_edge_type(str(edge.get("type") or ""))
        if etype != "member_of":
            continue
        src = str(edge.get("source") or "")
        tgt = str(edge.get("target") or "")
        src_node = nodes_by_id.get(src)
        if not src_node or str(src_node.get("type")) != "user":
            continue
        uname = _norm_user(_node_username(src_node))
        if not _user_is_owned(_node_username(src_node), owned) and not _user_is_pivot(
            _node_username(src_node), pivot_n
        ):
            continue
        tgt_node = nodes_by_id.get(tgt)
        if not tgt_node:
            continue
        if str(tgt_node.get("type")) == "group":
            gname = str(tgt_node.get("name") or "")
            if _is_privileged_group_name(gname):
                keep_ids.add(tgt)

    keep_ids.discard("")
    filtered_nodes = [n for n in nodes if str(n.get("id")) in keep_ids]
    kept = {str(n["id"]) for n in filtered_nodes}

    filtered_edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    for edge in edges:
        src = str(edge.get("source") or "")
        tgt = str(edge.get("target") or "")
        if src not in kept or tgt not in kept:
            continue
        etype = _normalize_edge_type(str(edge.get("type") or ""))
        if etype == "member_of":
            tgt_node = nodes_by_id.get(tgt)
            if tgt_node and str(tgt_node.get("type")) == "group":
                gname = str(tgt_node.get("name") or "")
                if not _is_privileged_group_name(gname):
                    src_node = nodes_by_id.get(src)
                    uname = _norm_user(_node_username(src_node)) if src_node else ""
                    if src_node and not _user_is_owned(
                        _node_username(src_node), owned
                    ) and not _user_is_pivot(_node_username(src_node), pivot_n):
                        continue
        key = edge.get("id") or f"{src}|{tgt}|{edge.get('type')}"
        if key in seen:
            continue
        seen.add(str(key))
        filtered_edges.append(edge)

    full_nodes = len(nodes)
    full_edges = len(edges)
    graph["nodes"] = filtered_nodes
    graph["edges"] = filtered_edges
    meta = dict(graph.get("meta") or {})
    meta.update(
        {
            "domain": domain.lower(),
            "node_count": len(filtered_nodes),
            "edge_count": len(filtered_edges),
            "focused": True,
            "full_node_count": full_nodes,
            "full_edge_count": full_edges,
        }
    )
    graph["meta"] = meta
    return graph


def node_display_name(nodes_by_id: dict[str, dict[str, Any]], node_id: str) -> str:
    node = nodes_by_id.get(node_id, {})
    return _node_label(node) if node else node_id
