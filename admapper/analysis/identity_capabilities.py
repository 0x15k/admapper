"""Per-owned-user outbound abuse capabilities — derived from workspace JSON."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from admapper.escalate.edges import collect_edges_from_pivot, sort_edges
from admapper.models.escalation import EscalationEdge
from admapper.report.engagement import _load_json


def _valid_cred_users(ws_path: Path) -> set[str]:
    creds = (_load_json(ws_path / "credentials.json") or {}).get("credentials") or []
    return {
        str(c.get("username", "")).lower()
        for c in creds
        if str(c.get("status")) == "valid"
    }


def _owned_lower(owned: list[str]) -> set[str]:
    return {u.lower().rstrip("$") for u in owned}


def _acl_findings(ws_path: Path) -> list[dict[str, Any]]:
    return list((_load_json(ws_path / "acl_findings.json") or {}).get("findings") or [])


def _graph_edges(ws_path: Path) -> list[dict[str, Any]]:
    return list((_load_json(ws_path / "graph.json") or {}).get("edges") or [])


def _user_node_id(username: str, domain: str) -> str:
    return f"user:{username.lower()}@{domain.lower()}"


def _acl_confirms(
    findings: list[dict[str, Any]],
    *,
    principal: str,
    target: str,
    right: str,
) -> bool:
    pl, tl, rl = principal.lower(), target.lower().rstrip("$"), right.lower()
    for f in findings:
        if str(f.get("principal", "")).lower() != pl:
            continue
        if str(f.get("right", "")).lower() != rl:
            continue
        ft = str(f.get("target_name", "")).lower().rstrip("$")
        if ft == tl or tl in ft:
            return True
    return False


def _graph_claims(
    edges: list[dict[str, Any]],
    *,
    principal: str,
    target: str,
    right: str,
    domain: str,
) -> bool:
    src = _user_node_id(principal, domain)
    rl = right.lower()
    tl = target.lower().rstrip("$")
    for e in edges:
        if str(e.get("source", "")) != src:
            continue
        if str(e.get("type", "")).lower() != rl:
            continue
        tgt = str(e.get("target", "")).lower()
        if tl in tgt:
            return True
    return False


def _mission_action(edge: EscalationEdge) -> str:
    tech = edge.technique.lower()
    exploit = {
        "genericwrite",
        "genericall",
        "readgmsapassword",
        "forcechangepassword",
        "addmember",
        "dcsync",
        "writedacl",
        "writeowner",
    }
    if edge.module == "acls" or tech in exploit:
        return "exploit"
    if (
        edge.module in {"wsus", "postex", "adcs"}
        or tech.startswith("wsus")
        or tech.startswith("esc")
    ):
        return "brief"
    return "exploit"


def _edge_enabled(
    edge: EscalationEdge,
    *,
    principal: str,
    owned: set[str],
    valid_users: set[str],
) -> tuple[bool, str | None]:
    pl = principal.lower()
    if pl not in owned and pl not in valid_users:
        return False, f"Primero compromete a {principal}"
    if pl not in valid_users:
        return False, f"Falta credencial válida de {principal} (LDAP/Kerberos)"
    if edge.target_owned:
        return False, f"{edge.target} ya está comprometido"
    if not edge.ready:
        return False, "Prerrequisitos no cumplidos"
    return True, None


def collect_identity_capabilities(
    ws_path: Path,
    *,
    domain: str,
    owned_users: list[str],
) -> list[dict[str, Any]]:
    """Per-owned-user outbound abuse — only what admapper indexed for that principal."""
    owned = _owned_lower(owned_users)
    valid = _valid_cred_users(ws_path)
    findings = _acl_findings(ws_path)
    graph_edges = _graph_edges(ws_path)
    identities: list[dict[str, Any]] = []

    principals = sorted(owned | valid)
    for principal in principals:
        if principal.endswith("$"):
            continue
        edges = collect_edges_from_pivot(
            pivot_user=principal,
            owned_users=owned_users,
            ws_path=ws_path,
            domain=domain,
        )
        caps: list[dict[str, Any]] = []
        for edge in sort_edges(edges):
            if edge.technique == "member_of":
                continue
            verified = _acl_confirms(
                findings,
                principal=principal,
                target=edge.target,
                right=edge.technique,
            )
            graph_only = not verified and _graph_claims(
                graph_edges,
                principal=principal,
                target=edge.target,
                right=edge.technique,
                domain=domain,
            )
            enabled, block = _edge_enabled(
                edge, principal=principal, owned=owned, valid_users=valid
            )
            caps.append(
                {
                    "technique": edge.technique,
                    "target": edge.target,
                    "title": edge.title,
                    "summary": edge.summary,
                    "verified": verified,
                    "graph_only": graph_only,
                    "enabled": enabled and verified,
                    "blocked_reason": block
                    if not enabled
                    else (
                        "Solo en grafo — ejecuta acls para verificar"
                        if graph_only
                        else None
                    ),
                    "action": _mission_action(edge),
                    "mitre": edge.mitre_id,
                    "op_id": edge.op_id or f"{principal}:{edge.technique}:{edge.target}",
                }
            )
        identities.append(
            {
                "username": principal,
                "owned": principal in owned,
                "cred_valid": principal in valid,
                "capabilities": caps,
            }
        )
    return identities
