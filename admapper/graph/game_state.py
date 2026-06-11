from __future__ import annotations

"""Objective game state — derived from workspace JSON, not hand-tuned scenarios."""

from pathlib import Path
from typing import Any

from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge, sort_edges
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
    if edge.module in {"wsus", "postex", "adcs"} or tech.startswith("wsus") or tech.startswith("esc"):
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


def collect_verified_missions(
    ws_path: Path,
    *,
    workspace: str,
    domain: str,
    owned_users: list[str],
) -> list[dict[str, Any]]:
    """Missions from ACL findings + pivot edges — verified abuse only."""
    owned = _owned_lower(owned_users)
    valid = _valid_cred_users(ws_path)
    missions: list[dict[str, Any]] = []

    for finding in _acl_findings(ws_path):
        principal = str(finding.get("principal", ""))
        if not principal:
            continue
        target = str(finding.get("target_name", ""))
        right = str(finding.get("right", ""))
        pl = principal.lower()
        enabled = pl in owned and pl in valid
        block: str | None = None
        if pl not in owned:
            block = f"Compromete a {principal} antes (loot / credencial)"
        elif pl not in valid:
            block = f"Verifica credencial de {principal} (creds verify)"

        missions.append(
            {
                "id": str(finding.get("id") or f"{principal}:{right}:{target}"),
                "principal": principal,
                "technique": right,
                "target": target,
                "summary": str(finding.get("summary") or ""),
                "verified": True,
                "enabled": enabled,
                "blocked_reason": block,
                "action": "exploit",
                "button": f"▶ {right} como {principal} → {target}",
                "reward": f"Abuso confirmado por LDAP ACL — {target}",
                "command": f"admapper exploit -w {workspace}  # principal {principal}",
                "requires_pivot": principal,
            }
        )

    for principal in sorted(owned):
        if principal.endswith("$"):
            continue
        edges = collect_edges_from_pivot(
            pivot_user=principal,
            owned_users=owned_users,
            ws_path=ws_path,
            domain=domain,
        )
        for edge in sort_edges(edges):
            if edge.technique == "member_of":
                continue
            key = f"{principal}:{edge.technique}:{edge.target}"
            if any(m.get("id") == edge.op_id or m.get("principal") == principal and m.get("target") == edge.target for m in missions):
                continue
            if _acl_confirms(
                _acl_findings(ws_path),
                principal=principal,
                target=edge.target,
                right=edge.technique,
            ):
                continue
            enabled, block = _edge_enabled(
                edge, principal=principal, owned=owned, valid_users=valid
            )
            if edge.module not in {"postex", "wsus", "adcs", "kerberos"}:
                continue
            missions.append(
                {
                    "id": edge.op_id or key,
                    "principal": principal,
                    "technique": edge.technique,
                    "target": edge.target,
                    "summary": edge.summary or edge.title,
                    "verified": edge.module != "acls",
                    "enabled": enabled,
                    "blocked_reason": block,
                    "action": _mission_action(edge),
                    "button": f"▶ {edge.title} ({principal})",
                    "reward": edge.title,
                    "command": f"admapper brief -w {workspace} --auto",
                    "requires_pivot": principal,
                }
            )
    return missions


def explain_target_access(
    ws_path: Path,
    *,
    domain: str,
    target: str,
    owned_users: list[str],
) -> dict[str, Any]:
    """Who can reach target — verified ACL vs speculative graph."""
    target_l = target.lower().rstrip("$")
    findings = _acl_findings(ws_path)
    graph_edges = _graph_edges(ws_path)
    owned = _owned_lower(owned_users)
    valid = _valid_cred_users(ws_path)

    direct_verified: list[str] = []
    direct_graph_only: list[str] = []
    for f in findings:
        if str(f.get("target_name", "")).lower().rstrip("$") != target_l:
            continue
        p = str(f.get("principal", ""))
        if p.lower() in owned or p.lower() in valid:
            direct_verified.append(f"{p} ({f.get('right')})")

    for user in owned | valid:
        if user.endswith("$"):
            continue
        for e in graph_edges:
            if str(e.get("source", "")) != _user_node_id(user, domain):
                continue
            if target_l not in str(e.get("target", "")).lower():
                continue
            right = str(e.get("type", ""))
            if not _acl_confirms(findings, principal=user, target=target, right=right):
                direct_graph_only.append(f"{user} ({right}) — no verificado en ACL")

    needs_chain = bool(direct_verified) and not any(
        p.split("(")[0].strip().lower() in owned for p in direct_verified
    )
    return {
        "target": target,
        "direct_verified": direct_verified,
        "direct_graph_only": direct_graph_only,
        "needs_intermediate": needs_chain,
        "note": (
            f"Solo {', '.join(direct_verified)} tiene ACL verificada sobre {target}"
            if direct_verified
            else (
                f"Nadie con ACL verificada — ejecuta acls con cada owned"
                if not direct_graph_only
                else f"Grafo sugiere {', '.join(direct_graph_only)} — verificar con acls"
            )
        ),
    }


def compute_stage_and_actions(
    ws_path: Path,
    *,
    workspace: str,
    dc_ip: str,
    domain: str,
    owned_users: list[str],
) -> dict[str, Any]:
    """Strict gating: only actions possible with current workspace facts."""
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    valid_users = _valid_cred_users(ws_path)
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    loot = _load_json(ws_path / "loot_manifest.json") or {}
    acl_n = len(_acl_findings(ws_path))
    owned = _owned_lower(owned_users)

    has_scan = bool(unauth.get("hosts"))
    users_data = _load_json(ws_path / "users.json") or {}
    has_users = bool(users_data.get("users"))
    has_creds = bool(valid_users)
    has_enum = bool(inv)
    has_loot = bool(loot.get("file_count")) or bool(loot.get("parsed_credentials"))
    has_acls = acl_n > 0

    actions: list[dict[str, Any]] = []

    if not has_scan:
        actions.append(
            {
                "id": "scan",
                "action": "scan",
                "button": "▶ ESCANEAR SIN AUTENTICACIÓN",
                "enabled": True,
                "reason": "LDAP · Kerberos 88 · SMB 445",
                "required": True,
            }
        )
        return {
            "stage": "recon",
            "stage_label": "Sin recon — empieza aquí",
            "game_over": False,
            "actions": actions,
        }

    if has_scan and not has_users:
        actions.append(
            {
                "id": "enum_users",
                "action": "enum",
                "button": "▶ ENUMERAR USUARIOS (IDENT)",
                "enabled": True,
                "reason": "SAMR · LDAP · AS-REP / Kerberoast surface",
                "required": True,
            }
        )

    if has_scan and has_users and not has_creds:
        actions.extend(
            [
                {
                    "id": "asreproast",
                    "action": "asreproast",
                    "button": "▶ AS-REP ROAST",
                    "enabled": True,
                    "reason": "P04 Credential access — cuentas sin pre-auth",
                    "required": False,
                },
                {
                    "id": "kerberoast",
                    "action": "kerberoast",
                    "button": "▶ KERBEROAST",
                    "enabled": True,
                    "reason": "P04 — SPNs con TGS roastable",
                    "required": False,
                },
                {
                    "id": "spray",
                    "action": "spray",
                    "button": "▶ PASSWORD SPRAY",
                    "enabled": True,
                    "reason": "P04 — prueba una contraseña en el user list",
                    "required": False,
                },
            ]
        )

    if not has_creds:
        actions.append(
            {
                "id": "cred",
                "action": "run",
                "button": "▶ INTRODUCIR CREDENCIALES",
                "enabled": True,
                "reason": "Sin credencial válida no hay enum ni loot — fin del engagement",
                "required": True,
            }
        )
        return {
            "stage": "need_creds",
            "stage_label": "Recon OK — necesitas credenciales",
            "game_over": True,
            "game_over_message": "Sin credenciales válidas el dominio no es accesible.",
            "actions": actions,
        }

    if not has_enum:
        actions.append(
            {
                "id": "enum",
                "action": "run",
                "button": "▶ ENUMERAR LDAP (autenticado)",
                "enabled": True,
                "reason": "BloodHound / auth_inventory",
                "required": True,
            }
        )

    if has_enum and not has_loot:
        actions.append(
            {
                "id": "loot",
                "action": "exploit",
                "button": "▶ RECOLECTAR LOOT SMB",
                "enabled": True,
                "reason": "SYSVOL · Logs · parse credenciales",
                "required": False,
            }
        )

    if has_enum and not has_acls and (owned or valid_users):
        actions.append(
            {
                "id": "acls",
                "action": "acls",
                "button": "▶ ANALIZAR ACLs (owned)",
                "enabled": True,
                "reason": "GenericWrite · ReadGMSAPassword · DCSync",
                "required": False,
            }
        )

    parsed_loot = loot.get("parsed_credentials") or []
    unverified_loot = [
        p
        for p in parsed_loot
        if str(p.get("username", "")).lower() not in valid_users
    ]
    if unverified_loot and has_creds:
        item = unverified_loot[0]
        user = str(item.get("username", ""))
        clue = str(item.get("password", ""))
        src = str(item.get("source_file", ""))[:40]
        actions.append(
            {
                "id": "verify_loot",
                "action": "run",
                "button": f"▶ VERIFICAR CREDENCIAL ({user})",
                "enabled": True,
                "reason": f"Pista en {src}: «{clue}» — tú eliges la contraseña",
                "required": False,
                "principal": user,
            }
        )

    missions = collect_verified_missions(
        ws_path, workspace=workspace, domain=domain, owned_users=owned_users
    )
    for m in missions:
        if m.get("enabled"):
            actions.append(
                {
                    "id": m["id"],
                    "action": m["action"],
                    "button": m["button"],
                    "enabled": True,
                    "reason": m.get("summary", "")[:120],
                    "required": False,
                    "mission": m,
                }
            )

    enabled_missions = [m for m in missions if m.get("enabled")]
    stage = "authenticated"
    if enabled_missions:
        stage = "escalate"
        stage_label = f"Escalada — {len(enabled_missions)} ruta(s) verificada(s)"
    elif has_acls:
        stage = "escalate_blocked"
        stage_label = "ACLs conocidas — falta owned/cred del principal"
    elif has_loot:
        stage = "loot_done"
        stage_label = "Loot OK — analiza ACLs"
    elif has_enum:
        stage = "enum_done"
        stage_label = "Enum OK — loot o ACLs"
    else:
        stage_label = "Autenticado — enumera el dominio"

    return {
        "stage": stage,
        "stage_label": stage_label,
        "game_over": False,
        "actions": actions,
    }


def build_objective_game_state(
    ws_path: Path,
    *,
    workspace: str,
    domain: str,
    owned_users: list[str],
    pivot_user: str | None,
) -> dict[str, Any]:
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", ""))
            break

    stage_info = compute_stage_and_actions(
        ws_path,
        workspace=workspace,
        dc_ip=dc_ip,
        domain=domain,
        owned_users=owned_users,
    )
    identities = collect_identity_capabilities(
        ws_path, domain=domain, owned_users=owned_users
    )
    missions = collect_verified_missions(
        ws_path, workspace=workspace, domain=domain, owned_users=owned_users
    )

    # Target intel for common gMSA in findings
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in _acl_findings(ws_path):
        t = str(f.get("target_name", ""))
        if t and t not in seen:
            seen.add(t)
            targets.append(
                explain_target_access(
                    ws_path, domain=domain, target=t, owned_users=owned_users
                )
            )

    pivot = pivot_user or (owned_users[-1] if owned_users else "")
    pivot_edges = (
        collect_edges_from_pivot(
            pivot_user=pivot,
            owned_users=owned_users,
            ws_path=ws_path,
            domain=domain,
        )
        if pivot
        else []
    )
    next_edge = pick_next_edge(pivot_edges) if pivot else None

    enabled = [m for m in missions if m.get("enabled")]
    primary = enabled[0] if enabled else (missions[0] if missions else None)

    return {
        **stage_info,
        "identities": identities,
        "missions": missions,
        "mission": primary,
        "targets": targets,
        "pivot": pivot,
        "next_edge": next_edge.to_dict() if next_edge else None,
    }
