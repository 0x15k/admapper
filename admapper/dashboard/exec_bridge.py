"""Dashboard command execution bridge — workspace_vars + substitution."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.creds.common import pick_dc_ip
from admapper.graph.edge_abuse import HopContext, _base_dn, substitute_command
from admapper.report.engagement import _load_json
from admapper.report.engagement_map import loot_clue_rows
from admapper.report.scenario import _best_cred_per_user, _normalize_username, cred_password_and_hash
from admapper.support.network import resolve_callback_ip

if TYPE_CHECKING:
    from admapper.support.session import Session

_SHELL_META = re.compile(r"[;&|`$()<>]")


def _password_from_loot(ws_path: Path, username: str) -> str:
    if not username:
        return ""
    want = _normalize_username(username)
    for clue in loot_clue_rows(ws_path):
        if _normalize_username(clue.get("user", "")) == want:
            pwd = str(clue.get("string") or "").strip()
            if pwd:
                return pwd
    manifest = _load_json(ws_path / "loot_manifest.json") or {}
    for item in manifest.get("parsed_credentials") or []:
        if _normalize_username(item.get("username", "")) == want:
            pwd = str(item.get("password") or "").strip()
            if pwd:
                return pwd
    return ""


def _resolve_attacker_ip(ws_path: Path, overrides: dict[str, str]) -> str:
    for key in ("ATTACKER_IP", "attacker_ip", "LHOST", "lhost"):
        val = str(overrides.get(key) or "").strip()
        if val:
            return val
    setup = _load_json(ws_path / "cheatsheet_vars.json") or {}
    for key in ("ATTACKER_IP", "attacker_ip", "LHOST", "lhost"):
        val = str(setup.get(key) or "").strip()
        if val:
            return val
    for name in ("postex_deploy.json", "postex_last_run.json"):
        data = _load_json(ws_path / name) or {}
        val = str(data.get("callback_ip") or data.get("lhost") or "").strip()
        if val:
            return val
    detected = resolve_callback_ip()
    return detected or ""


def _resolve_ca_name(adcs: dict[str, Any]) -> str:
    direct = str(adcs.get("ca_name") or "").strip()
    if direct:
        return direct
    for service in adcs.get("enrollment_services") or []:
        if isinstance(service, dict):
            name = str(service.get("name") or "").strip()
            if name:
                return name
    for ca in adcs.get("certificate_authorities") or adcs.get("cas") or []:
        if isinstance(ca, dict):
            name = str(ca.get("name") or ca.get("ca_name") or "").strip()
            if name:
                return name
    return ""


def _resolve_template(ws_path: Path, adcs: dict[str, Any], findings: dict[str, Any]) -> str:
    wsus = _load_json(ws_path / "wsus_ops.json") or {}
    for op in wsus.get("operations") or []:
        template = str(op.get("template") or "").strip()
        if template:
            return template

    ranked: list[tuple[int, str]] = []
    for item in findings.get("findings") or []:
        if not isinstance(item, dict):
            continue
        template = str(item.get("template") or "").strip()
        if not template:
            continue
        score = 0
        if item.get("wsus_chain_step"):
            score += 100
        esc = str(item.get("esc") or "").lower()
        if esc in {"esc1", "esc4", "template_enrollment"}:
            score += 50
        if str(item.get("severity") or "").lower() in {"critical", "high"}:
            score += 10
        ranked.append((score, template))
    if ranked:
        ranked.sort(key=lambda row: row[0], reverse=True)
        return ranked[0][1]

    for item in adcs.get("templates") or []:
        if not isinstance(item, dict):
            continue
        if item.get("low_priv_enrollment"):
            name = str(item.get("name") or "").strip()
            if name:
                return name
    return ""


def _secrets_for_user(
    ws_path: Path,
    username: str,
    best: dict[str, dict],
) -> tuple[str, str]:
    key = _normalize_username(username)
    if key and key in best:
        password, nthash = cred_password_and_hash(best[key])
        if password or nthash:
            return password, nthash
    password = _password_from_loot(ws_path, username)
    return password, ""


def build_workspace_vars(session: Session) -> dict[str, str]:
    """Single source for cheatsheet vars (/api/state + /api/exec)."""
    if session.workspace is None:
        return {}
    ws = session.workspace
    ws_path = session.workspaces.path_for(ws.name)
    return build_cheatsheet_vars(
        ws_path,
        workspace=ws.name,
        domain=ws.domain or "",
        pivot=ws.pivot_user or "",
        owned_users=list(ws.owned_users or []),
        dc_ip=pick_dc_ip(session) or "",
    )


def build_cheatsheet_vars(
    ws_path: Path,
    *,
    workspace: str,
    domain: str = "",
    pivot: str = "",
    owned_users: list[str] | None = None,
    dc_ip: str = "",
) -> dict[str, str]:
    user = pivot.strip()
    password = ""
    nthash = ""

    creds_path = ws_path / "credentials.json"
    creds_data = _load_json(creds_path) or {}
    best = _best_cred_per_user(creds_data.get("credentials") or [])

    if pivot:
        password, nthash = _secrets_for_user(ws_path, pivot, best)
    if not password and not nthash and best:
        first_user = next(iter(best.keys()), "")
        entry = best.get(first_user) or {}
        user = user or str(entry.get("username") or first_user)
        password, nthash = _secrets_for_user(ws_path, user, best)
    if pivot and not password:
        password = _password_from_loot(ws_path, pivot)

    overrides: dict[str, str] = {}
    extra_path = ws_path / "cheatsheet_vars.json"
    if extra_path.is_file():
        try:
            overrides = {k: str(v) for k, v in json.loads(extra_path.read_text(encoding="utf-8")).items()}
        except (OSError, json.JSONDecodeError, TypeError):
            overrides = {}

    attacker_ip = _resolve_attacker_ip(ws_path, overrides)
    adcs = _load_json(ws_path / "adcs_inventory.json") or {}
    findings = _load_json(ws_path / "adcs_findings.json") or {}
    ca_name = _resolve_ca_name(adcs)
    template = _resolve_template(ws_path, adcs, findings)

    base = {
        "DOMAIN": domain,
        "DC_IP": dc_ip,
        "USERNAME": user,
        "PASSWORD": password,
        "NTLM_HASH": nthash,
        "ATTACKER_IP": attacker_ip,
        "CA_NAME": ca_name,
        "TEMPLATE": template,
        "workspace": workspace,
        "BASE_DN": _base_dn(domain),
        "TARGET_USER": overrides.get("TARGET_USER", ""),
        "TARGET_COMPUTER": overrides.get("TARGET_COMPUTER", ""),
        "DOMAIN_SID": overrides.get("DOMAIN_SID", ""),
    }
    for key, val in overrides.items():
        if val:
            base[key.upper() if key.islower() else key] = str(val)
    if not base.get("ATTACKER_IP") and attacker_ip:
        base["ATTACKER_IP"] = attacker_ip
    if base.get("ATTACKER_IP") and not base.get("LHOST"):
        base["LHOST"] = base["ATTACKER_IP"]
    if not base.get("CA_NAME") and ca_name:
        base["CA_NAME"] = ca_name
    if not base.get("TEMPLATE") and template:
        base["TEMPLATE"] = template
    return base


def hop_context_from_dict(data: dict[str, Any] | None) -> HopContext | None:
    if not data:
        return None
    return HopContext(
        from_label=str(data.get("from") or data.get("from_label") or ""),
        to_label=str(data.get("to") or data.get("to_label") or ""),
        to_short=str(data.get("to_short") or data.get("toShort") or ""),
        to_dn=str(data.get("to_dn") or data.get("toDN") or ""),
    )


def resolve_argv(command: str, *, allow_shell: bool = False) -> list[str]:
    text = command.strip()
    if not text:
        raise ValueError("empty command")
    if not allow_shell and _SHELL_META.search(text):
        raise ValueError("command contains shell metacharacters — use argv-safe templates only")
    if text.startswith("admapper "):
        return ["admapper", *shlex.split(text[len("admapper ") :])]
    return shlex.split(text)


def prepare_exec_request(
    body: dict[str, Any],
    session: Session,
    *,
    substitute: bool = True,
) -> tuple[list[str], str]:
    """Return (argv, resolved_command_string) from /api/exec body."""
    template = str(body.get("command_template") or body.get("command") or "").strip()
    if not template:
        raise ValueError("command_template required")
    ws_vars = dict(body.get("workspace_vars") or {})
    if not ws_vars:
        ws_vars = build_workspace_vars(session)
    else:
        merged = build_workspace_vars(session)
        merged.update({k: str(v) for k, v in ws_vars.items() if v is not None})
        ws_vars = merged
    hop = hop_context_from_dict(body.get("hop_context"))
    resolved = (
        substitute_command(template, ws_vars, hop)
        if substitute and body.get("substitute", True)
        else template
    )
    argv = resolve_argv(resolved)
    return argv, resolved


def save_cheatsheet_var_overrides(ws_path: Path, updates: dict[str, str]) -> dict[str, str]:
    path = ws_path / "cheatsheet_vars.json"
    current: dict[str, str] = {}
    if path.is_file():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            current = {}
    current.update({k: str(v) for k, v in updates.items() if v is not None})
    path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    return current


def load_findings_notes(ws_path: Path) -> list[dict[str, Any]]:
    path = ws_path / "findings_notes.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return list(data.get("notes") or data if isinstance(data, list) else [])
    except (OSError, json.JSONDecodeError):
        return []


def save_findings_notes(ws_path: Path, notes: list[dict[str, Any]]) -> None:
    path = ws_path / "findings_notes.json"
    path.write_text(json.dumps({"notes": notes}, indent=2) + "\n", encoding="utf-8")
