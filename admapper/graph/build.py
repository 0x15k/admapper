from __future__ import annotations

from typing import Any

from admapper.graph.catalog import is_high_value_group


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


def node_display_name(nodes_by_id: dict[str, dict[str, Any]], node_id: str) -> str:
    node = nodes_by_id.get(node_id, {})
    return _node_label(node) if node else node_id
