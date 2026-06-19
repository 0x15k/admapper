"""AD Ops game — workspace payload and graph enrichment for the web UI."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from admapper.analysis.engagement_intel import build_engagement_intel
from admapper.core.operator_setup import build_operator_setup
from admapper.methodology.unified import (
    ENGAGEMENT_FRAMEWORK,
    build_study_map,
)
from admapper.report.engagement_map import loot_clue_rows
from admapper.report.methodology import enum_highlights, methodology_lines
from admapper.creds.common import collect_gained_hashes, format_admapper_winrm_pth
from admapper.report.engagement import _load_json
from admapper.report.engagement_map import _acl_exploit_blocker
from admapper.report.scenario import _best_cred_per_user
from admapper.guides.pentest_book import build_pentest_book
from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge
from admapper.graph.game_progress import GameProgress, filtered_loot_clues
from admapper.graph.game_state import build_objective_game_state
from admapper.graph.identity_lens import (
    build_identity_lens,
    build_selectable_identities,
    filter_actions_for_pivot,
    filter_intel_for_pivot,
    filter_targets_for_pivot,
)
from admapper.graph.topology import build_network_topology
from admapper.models.escalation import EscalationEdge
from admapper.graph.web import build_graph_payload


def _esc(text: str) -> str:
    return html.escape(str(text or ""))


def _account_base(name: str) -> str:
    return str(name or "").lower().rstrip("$").split("@")[0]


def _phase_status(ws_path: Path) -> list[dict[str, Any]]:
    """Unified AD chain (CRTP core) — shortened game bar."""
    from admapper.methodology.unified import game_phase_status

    return game_phase_status(ws_path)


_EXPLOIT_TECHNIQUES = frozenset(
    {
        "genericwrite",
        "genericall",
        "readgmsapassword",
        "forcechangepassword",
        "addmember",
        "dcsync",
        "writedacl",
        "writeowner",
    }
)


def _mission_action(edge: EscalationEdge) -> str:
    tech = edge.technique.lower()
    if edge.module == "acls" or tech in _EXPLOIT_TECHNIQUES:
        return "exploit"
    if edge.module in {"wsus", "postex", "adcs"} or tech.startswith("wsus") or tech.startswith("esc"):
        return "brief"
    return "exploit"


def _mission_button(edge: EscalationEdge) -> str:
    tech = edge.technique.lower()
    target = edge.target or "?"
    labels = {
        "genericwrite": f"▶ EXPLOTAR GenericWrite → {target}",
        "readgmsapassword": f"▶ LEER PASSWORD gMSA {target}",
        "genericall": f"▶ GenericAll → {target}",
        "forcechangepassword": f"▶ CAMBIAR PASSWORD → {target}",
        "dcsync": "▶ DCSYNC",
        "wsus_cert_chain": "▶ CADENA WSUS + AD CS",
        "wsus_spoof": "▶ WSUS SPOOF",
        "dll_hijack_scheduled_task": "▶ DLL HIJACK (tarea programada)",
    }
    return labels.get(tech, f"▶ {edge.title}")


def _mission_reward(edge: EscalationEdge) -> str:
    tech = edge.technique.lower()
    if tech in {"genericwrite", "readgmsapassword"}:
        return f"Contraseña/hash de {edge.target or 'cuenta'} → nuevo pivot"
    if tech == "dcsync":
        return "Hashes de Domain Admins"
    if "wsus" in tech:
        return "Shell como SYSTEM / DA"
    return "Nuevo acceso en la cadena"


def _mission_from_edge(edge: EscalationEdge, *, workspace: str, pivot: str) -> dict[str, Any]:
    action = _mission_action(edge)
    cmd = {
        "exploit": f"admapper exploit -w {workspace}",
        "brief": f"admapper brief -w {workspace} --auto",
        "acls": f"admapper acls -w {workspace}",
        "scan": f"admapper scan -H <DC>",
        "run": f"admapper run -w {workspace} -u <user> -p '<pass>'",
    }.get(action, f"admapper {action} -w {workspace}")
    return {
        "id": edge.op_id or f"{edge.technique}:{edge.target}",
        "title": edge.title,
        "technique": edge.technique,
        "target": edge.target,
        "summary": edge.summary or edge.title,
        "severity": edge.severity,
        "mitre": edge.mitre_id,
        "action": action,
        "button": _mission_button(edge),
        "reward": _mission_reward(edge),
        "command": cmd,
        "pivot": pivot,
        "ready": edge.ready and not edge.target_owned,
    }


def _tag_graph_missions(graph: dict[str, Any], quests: list[dict[str, Any]]) -> None:
    """Link vis-network edges to verified missions for click-to-exploit."""
    by_key = {
        (q["technique"].lower(), q["target"].lower().rstrip("$"), str(q.get("principal", "")).lower()): q["id"]
        for q in quests
        if q.get("technique") and q.get("target") and q.get("verified")
    }
    for edge in graph.get("edges") or []:
        label = str(edge.get("label", "")).lower().replace(" ", "")
        for (tech, tgt, _principal), mid in by_key.items():
            if (label == tech or tech in label) and tgt in str(edge.get("to", "")).lower():
                edge["mission_id"] = mid
                edge["width"] = 4
                edge["color"] = {"color": "#f59e0b", "highlight": "#3dffcf"}
                break
        if edge.get("mission_id"):
            continue
        if label and label not in {"member_of", "member_of_domain"}:
            edge["dashes"] = True
            edge["color"] = {"color": "#6b7280"}
            edge["title"] = (edge.get("title") or label) + " (no verificado — ejecuta acls)"


def _enrich_graph_for_recon(graph: dict[str, Any], unauth: dict[str, Any]) -> None:
    """Placeholder nodes when graph.json is empty — fixes blank center map."""
    if graph.get("nodes"):
        return
    hosts = unauth.get("hosts") or []
    dc = next((h for h in hosts if h.get("is_domain_controller")), None)
    if not dc and hosts:
        dc = hosts[0]
    if not dc:
        graph["nodes"] = [
            {
                "id": "operator",
                "label": "OPERATOR",
                "group": "operator",
                "color": "#3dffcf",
                "title": "Esperando recon…",
                "font": {"color": "#080b10"},
                "shape": "box",
            }
        ]
        graph["edges"] = []
        return

    addr = str(dc.get("address", "?"))
    hostname = str(dc.get("hostname") or addr)
    ports = dc.get("open_ports") or [88, 389, 445]
    port_s = ",".join(str(p) for p in ports[:6])
    dc_id = f"dc:{addr}"
    graph["nodes"] = [
        {
            "id": "operator",
            "label": "OPERATOR",
            "group": "operator",
            "color": "#3dffcf",
            "title": "Tu posición",
            "font": {"color": "#080b10"},
            "shape": "box",
        },
        {
            "id": dc_id,
            "label": f"DC\n{hostname[:18]}",
            "group": "dc",
            "color": "#6366f1",
            "title": f"LDAP/Kerberos/SMB\n{addr}\nports: {port_s}",
            "font": {"color": "#f8fafc"},
            "shape": "box",
        },
    ]
    graph["edges"] = [
        {
            "from": "operator",
            "to": dc_id,
            "label": "RECON",
            "dashes": True,
            "color": {"color": "#3dffcf"},
            "width": 2,
        }
    ]


def build_game_payload(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
    game_progress: GameProgress | None = None,
) -> dict[str, Any]:
    if game_progress is not None:
        owned = list(game_progress.owned_users)
    else:
        owned = list(owned_users or [])
    state = _load_json(ws_path / "state.json") or {}
    pivot = (
        pivot_user
        or state.get("pivot_user")
        or (owned[-1] if owned else "")
    )
    pivot = str(pivot or "").strip()

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    has_scan = bool(unauth.get("hosts"))
    if game_progress is not None:
        has_scan = game_progress.scan
    discovered_domain = str(unauth.get("domain") or "").strip()
    domain_known = bool(discovered_domain and has_scan)
    domain_s = discovered_domain if domain_known else (domain if domain and has_scan else "???")
    dc_ip = ""
    dc_host = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", ""))
            dc_host = str(host.get("hostname") or "")
            break
    if not dc_ip:
        state = _load_json(ws_path / "state.json") or {}
        dc_ip = str(state.get("hosts") or "").strip()

    graph = build_graph_payload(
        ws_path,
        domain=domain_s,
        pivot_user=pivot,
        owned_users=owned,
        tactical=True,
    )
    _enrich_graph_for_recon(graph, unauth)

    game_state = build_objective_game_state(
        ws_path,
        workspace=workspace,
        domain=domain_s,
        owned_users=owned,
        pivot_user=pivot,
        game_progress=game_progress,
    )
    quests = game_state.get("missions") or []
    mission = game_state.get("mission")
    actions = game_state.get("actions") or []
    if not mission and actions:
        primary = next((a for a in actions if a.get("required")), actions[0])
        mission = {
            "id": primary.get("id"),
            "action": primary.get("action"),
            "button": primary.get("button"),
            "summary": primary.get("reason"),
            "enabled": primary.get("enabled", True),
        }

    _tag_graph_missions(graph, quests)

    next_edge_data = game_state.get("next_edge") or {}
    next_hop_cmd = graph.get("next_hop_cmd")
    if game_progress is not None and not game_progress.exploit:
        next_hop_cmd = None
        graph = {**graph, "gained_hashes": [], "next_hop_cmd": None}
    objective = {
        "headline": graph.get("next_hop") or next_edge_data.get("title") or game_state.get("stage_label", ""),
        "technique": next_edge_data.get("technique", ""),
        "target": next_edge_data.get("target", ""),
        "command": next_hop_cmd or (mission or {}).get("command", ""),
        "blocker": graph.get("acl_blocker") or _acl_exploit_blocker(ws_path),
    }

    cred_inventory: list[dict[str, str]] = []
    if game_progress is None:
        cred_iter = _best_cred_per_user(
            (_load_json(ws_path / "credentials.json") or {}).get("credentials") or []
        ).values()
    else:
        cred_iter = [
            {"username": u, "status": "valid", "source": "game"}
            for u in game_progress.verified_users
        ]
    for cred in cred_iter:
        cred_inventory.append(
            {
                "user": str(cred.get("username", "")),
                "status": str(cred.get("status", "")),
                "source": str(cred.get("source", ""))[:32],
            }
        )

    clues = filtered_loot_clues(ws_path, game_progress)
    topology = build_network_topology(
        ws_path,
        domain=domain_s if domain_known else None,
        owned_users=owned,
        reveal_scan=has_scan,
        reveal_enum=game_progress is None or game_progress.enum_users,
    )
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    graph_mode = "network"
    if inv and (game_progress is None or game_progress.enum_users):
        graph_mode = "hybrid"
    engagement_intel = build_engagement_intel(
        ws_path,
        workspace=workspace,
        domain=domain_s if domain_known else domain,
        owned_users=owned,
        game_progress=game_progress,
    )
    selectable = build_selectable_identities(
        ws_path,
        domain=domain_s if domain_known else (domain or ""),
        owned_users=owned,
        game_progress=game_progress,
    )
    for row in selectable:
        if domain_s and domain_s != "???" and row.get("username"):
            row["lens"] = build_identity_lens(
                ws_path,
                workspace=workspace,
                domain=domain_s,
                pivot_user=str(row["username"]),
                owned_users=owned,
                game_progress=game_progress,
            )
            if row.get("selectable") == "view":
                row["view_lens"] = row["lens"]
    identity_lens = (
        build_identity_lens(
            ws_path,
            workspace=workspace,
            domain=domain_s,
            pivot_user=pivot,
            owned_users=owned,
            game_progress=game_progress,
        )
        if pivot and domain_s and domain_s != "???"
        else {}
    )
    if pivot and identity_lens:
        engagement_intel = filter_intel_for_pivot(engagement_intel, pivot, identity_lens)
        actions = filter_actions_for_pivot(actions, pivot=pivot)
        pivot_quests = [
            q
            for q in quests
            if str(q.get("principal", "")).lower() == pivot.lower()
        ]
        if pivot_quests:
            quests = pivot_quests
        pm = identity_lens.get("primary_mission")
        if pm:
            mission = pm
        pivot_targets = filter_targets_for_pivot(game_state.get("targets") or [], pivot=pivot)
        if pivot_targets:
            game_state = dict(game_state)
            game_state["targets"] = pivot_targets
        ne = identity_lens.get("next_edge")
        if ne:
            objective = {
                **objective,
                "headline": ne.get("title") or objective.get("headline", ""),
                "technique": ne.get("technique") or objective.get("technique", ""),
                "target": ne.get("target") or objective.get("target", ""),
            }
    game_state = dict(game_state)
    game_state["actions"] = actions

    if game_progress is not None:
        progress_flags = {
            "scan": game_progress.scan,
            "enum_users": game_progress.enum_users,
            "loot": game_progress.loot,
            "acls": game_progress.acls,
            "exploit": game_progress.exploit,
        }
    else:
        progress_flags = {
            "scan": True,
            "enum_users": True,
            "loot": True,
            "acls": True,
            "exploit": True,
        }

    hashes = graph.get("gained_hashes") or []
    if game_progress is not None and not game_progress.exploit:
        hashes = []

    pth_accounts = {_account_base(h.get("account", "")) for h in hashes}
    pth_sessions: list[dict[str, str]] = []
    for item in hashes:
        account = str(item.get("account", ""))
        nthash = str(item.get("nthash", ""))
        if not account or not nthash:
            continue
        _, winrm_cmd = format_admapper_winrm_pth(
            account=account,
            nthash=nthash,
            domain=domain_s if domain_known else domain,
            ws_path=ws_path,
            fallback_ip=dc_ip or None,
        )
        pth_sessions.append(
            {
                "account": account,
                "nthash": nthash,
                "winrm_cmd": winrm_cmd,
            }
        )

    cred_inventory = [c for c in cred_inventory if _account_base(c.get("user", "")) not in pth_accounts]

    return {
        "meta": {
            "workspace": workspace,
            "domain": domain_s,
            "domain_known": domain_known,
            "blackbox": not has_scan,
            "target_ip": dc_ip,
            "dc_ip": dc_ip if has_scan else dc_ip,
            "dc_host": dc_host if has_scan and dc_host not in {"-", "?"} else "",
        },
        "topology": topology,
        "graph_mode": graph_mode,
        "player": {"pivot": pivot, "owned": owned},
        "selectable_identities": selectable,
        "identity_lens": identity_lens,
        "phases": _phase_status(ws_path),
        "game": game_state,
        "mission": mission,
        "quests": quests,
        "actions": actions,
        "objective": objective,
        "methodology": methodology_lines(ws_path),
        "highlights": enum_highlights(ws_path) if game_progress is None or game_progress.enum_users else [],
        "clues": clues,
        "creds": cred_inventory,
        "hashes": hashes,
        "pth_sessions": pth_sessions,
        "progress": progress_flags,
        "graph": graph,
        "engagement_intel": engagement_intel,
        "operator_setup": build_operator_setup(ws_path, dc_ip=dc_ip, dc_host=dc_host),
        "engagement_framework": ENGAGEMENT_FRAMEWORK,
        "study_map": build_study_map(),
        "pentest_book": build_pentest_book(),
    }


