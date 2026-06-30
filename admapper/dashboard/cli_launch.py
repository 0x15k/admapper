"""Seed workspace + cheatsheet vars from CLI flags or dashboard UI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.dashboard.exec_bridge import build_cheatsheet_vars, save_cheatsheet_var_overrides
from admapper.dashboard.target_ip import apply_target_ip_change, first_host_token
from admapper.models.credential import CredentialStatus, CredentialType
from admapper.report.engagement import _load_json
from admapper.support.network import resolve_callback_ip

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass(frozen=True)
class DashboardLaunchContext:
    ws_path: Path
    workspace: str
    domain: str | None
    pivot_user: str | None
    owned_users: list[str]
    host: str | None
    cheatsheet_vars: dict[str, str]


def workspace_readiness(vars: dict[str, str]) -> dict[str, Any]:
    """Whether the operator has filled enough vars for scan vs authenticated ops."""
    dc = str(vars.get("DC_IP") or vars.get("dc_ip") or "").strip()
    user = str(vars.get("USERNAME") or vars.get("username") or "").strip()
    password = str(vars.get("PASSWORD") or vars.get("password") or "").strip()
    nthash = str(vars.get("NTLM_HASH") or vars.get("nthash") or "").strip()
    missing: list[str] = []
    if not dc:
        missing.append("DC_IP")
    if not user:
        missing.append("USERNAME")
    if not password and not nthash:
        missing.append("PASSWORD or NTLM_HASH")
    return {
        "scan_ready": bool(dc),
        "auth_ready": bool(dc and user and (password or nthash)),
        "missing": missing,
    }


def build_blank_dashboard_payload(
    workspaces: Any,
    *,
    pending_dc_ip: str | None = None,
) -> dict[str, Any]:
    """Minimal /api/state payload before the operator picks a workspace."""
    dc = first_host_token(pending_dc_ip) if pending_dc_ip else ""
    cheatsheet_vars: dict[str, str] = {}
    if dc:
        cheatsheet_vars["DC_IP"] = dc
    return {
        "workspace_required": True,
        "available_workspaces": workspaces.list_workspaces(),
        "meta": {
            "workspace": "",
            "domain": "",
            "domain_known": False,
            "blackbox": True,
            "target_ip": dc,
            "dc_ip": dc,
            "dc_host": "",
        },
        "topology": {"nodes": [], "edges": []},
        "graph_mode": "empty",
        "player": {"pivot": None, "owned": [], "owned_methods": {}, "pivot_protected": False},
        "selectable_identities": [],
        "identity_lens": {},
        "phases": {},
        "dashboard": {"stage": "setup", "stage_label": "Create workspace"},
        "mission": {},
        "quests": [],
        "attack_paths": [],
        "quick_wins": [],
        "actions": [],
        "objective": {},
        "methodology": [],
        "highlights": [],
        "clues": [],
        "creds": [],
        "hashes": [],
        "pth_sessions": [],
        "escalation_target": "",
        "progress": {},
        "effective_progress": {},
        "next_action": {},
        "graph": {"nodes": [], "edges": []},
        "engagement_intel": {},
        "findings": {"findings": []},
        "operator_setup": {
            "clock_ready": False,
            "hosts_entry": None,
            "notes": ["Create or open a workspace to begin."],
        },
        "engagement_framework": "",
        "study_map": {},
        "pentest_book": {},
        "cheatsheet_vars": cheatsheet_vars,
        "findings_notes": {},
        "workspace_readiness": workspace_readiness(cheatsheet_vars),
    }


def seed_workspace_from_vars(
    session: Session,
    raw: dict[str, Any],
    *,
    source: str = "ui",
    verify_cred: bool = False,
) -> dict[str, str]:
    """Persist operator vars into workspace JSON + cheatsheet_vars (UI or CLI)."""
    if session.workspace is None:
        return {}

    from admapper.cli.commands import dispatch

    ws = session.workspace
    ws_path = session.workspaces.path_for(ws.name)

    old_ip = first_host_token(ws.hosts)

    host_s = str(
        raw.get("DC_IP")
        or raw.get("dc_ip")
        or raw.get("host")
        or raw.get("ip")
        or ws.hosts
        or ""
    ).strip()
    hosts_meta: dict[str, Any] | None = None
    if host_s:
        first_host = host_s.split()[0]
        if first_host != old_ip:
            hosts_meta = apply_target_ip_change(session, first_host)
            host_s = first_host
        else:
            dispatch(session, f"set hosts {first_host}")
            host_s = first_host

    domain_s = str(raw.get("DOMAIN") or raw.get("domain") or ws.domain or "").strip()
    if domain_s:
        dispatch(session, f"set domain {domain_s}")

    user_s = str(raw.get("USERNAME") or raw.get("username") or raw.get("user") or ws.pivot_user or "").strip()
    from admapper.support.owned import is_valid_owned_username, normalize_username

    user_s = normalize_username(user_s)
    pass_s = str(raw.get("PASSWORD") or raw.get("password") or raw.get("pass") or "").strip()
    nthash_s = str(raw.get("NTLM_HASH") or raw.get("nthash") or raw.get("hash") or "").strip()
    lhost_s = str(raw.get("ATTACKER_IP") or raw.get("attacker_ip") or raw.get("lhost") or "").strip()

    # Vars seed sets pivot hint only — owned/verified come from successful auth, not typing.
    if user_s and is_valid_owned_username(user_s):
        ws.pivot_user = user_s

    state_path = ws_path / "state.json"
    state = dict(_load_json(state_path) or {})
    if host_s:
        state["hosts"] = host_s
    if domain_s:
        state["domain"] = domain_s
    if user_s and is_valid_owned_username(user_s):
        state["pivot_user"] = user_s
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if session.credentials is not None and user_s:
        store = session.credentials
        if pass_s:
            existing = next((c for c in store.list() if c.username.lower() == user_s.lower()), None)
            if existing is not None:
                store.remove(existing.id)
            cred = store.add(
                user_s,
                pass_s,
                domain=domain_s or None,
                cred_type=CredentialType.PASSWORD,
                source=source,
            )
            if verify_cred:
                store.mark_status(cred.id, CredentialStatus.VALID)
        elif nthash_s:
            existing = next((c for c in store.list() if c.username.lower() == user_s.lower()), None)
            if existing is not None:
                store.remove(existing.id)
            cred = store.add(
                user_s,
                nthash_s,
                domain=domain_s or None,
                cred_type=CredentialType.NTLM,
                source=source,
            )
            if verify_cred:
                store.mark_status(cred.id, CredentialStatus.VALID)

    attacker_ip = lhost_s or resolve_callback_ip() or ""

    seeds: dict[str, str] = {"workspace": ws.name}
    if host_s:
        seeds["DC_IP"] = host_s
    if domain_s:
        seeds["DOMAIN"] = domain_s
    if user_s:
        seeds["USERNAME"] = user_s
    if pass_s:
        seeds["PASSWORD"] = pass_s
    if nthash_s:
        seeds["NTLM_HASH"] = nthash_s
    if attacker_ip:
        seeds["ATTACKER_IP"] = attacker_ip

    current = dict(_load_json(ws_path / "cheatsheet_vars.json") or {})
    for key, val in seeds.items():
        if val:
            current[key] = val
    for key, val in raw.items():
        if key in {"vars", "workspace_vars"}:
            continue
        if val is not None and str(val).strip():
            norm = key if key == "workspace" else (key.upper() if key.islower() else key)
            current[norm] = str(val)
    save_cheatsheet_var_overrides(ws_path, current)

    session.persist_workspace()

    vars_out = build_cheatsheet_vars(
        ws_path,
        workspace=ws.name,
        domain=domain_s,
        pivot=user_s,
        owned_users=list(ws.owned_users or []),
        dc_ip=host_s,
    )
    if hosts_meta and hosts_meta.get("hosts_message"):
        vars_out["_hosts_message"] = str(hosts_meta["hosts_message"])
    return vars_out


def apply_cli_launch_context(
    session: Session,
    *,
    host: str | None = None,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    lhost: str | None = None,
) -> dict[str, str]:
    """CLI convenience — same seed path as the dashboard UI."""
    raw: dict[str, Any] = {}
    if host:
        raw["DC_IP"] = host
    if username:
        raw["USERNAME"] = username
    if password:
        raw["PASSWORD"] = password
    if domain:
        raw["DOMAIN"] = domain
    if lhost:
        raw["ATTACKER_IP"] = lhost
    return seed_workspace_from_vars(session, raw, source="cli_launch", verify_cred=bool(username and password))


def build_launch_context(
    session: Session,
    *,
    host: str | None = None,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    lhost: str | None = None,
) -> DashboardLaunchContext:
    """Apply CLI seeds when provided; otherwise load existing workspace vars."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    ws = session.workspace
    ws_path = session.workspaces.path_for(ws.name)
    has_cli = any((host, username, password, domain, lhost))
    cheatsheet_vars = (
        apply_cli_launch_context(
            session,
            host=host,
            username=username,
            password=password,
            domain=domain,
            lhost=lhost,
        )
        if has_cli
        else build_cheatsheet_vars(
            ws_path,
            workspace=ws.name,
            domain=ws.domain or "",
            pivot=ws.pivot_user or "",
            owned_users=list(ws.owned_users or []),
            dc_ip=first_host_token(ws.hosts),
        )
    )

    ws = session.workspace
    host_ip = first_host_token(host or ws.hosts) or None
    return DashboardLaunchContext(
        ws_path=ws_path,
        workspace=ws.name,
        domain=ws.domain or cheatsheet_vars.get("DOMAIN") or None,
        pivot_user=ws.pivot_user or cheatsheet_vars.get("USERNAME") or None,
        owned_users=list(ws.owned_users or []),
        host=host_ip,
        cheatsheet_vars=cheatsheet_vars,
    )
