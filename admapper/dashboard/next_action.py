"""Resolve the operator's next command from workspace artifacts (not stale UI flags)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from admapper.report.engagement import _load_json

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SKIP_POSTEX = frozenset({"local_shell_blocked"})

_POSTEX_RUN_TECHNIQUES = frozenset({"dll_hijack_scheduled_task"})


def _postex_template_ctx(ws_path: Path, workspace: str, op: dict[str, Any]) -> dict[str, str]:
    from admapper.postex.templates import build_template_context

    state = _load_json(ws_path / "state.json") or {}
    domain = str(state.get("domain") or workspace)
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    host = str(op.get("target_host") or "").strip()
    if not host:
        for item in unauth.get("hosts") or []:
            if item.get("is_domain_controller"):
                host = str(item.get("address") or "")
                break
    pivot = str(state.get("pivot_user") or "").strip()
    if not pivot:
        ctx_raw = str(op.get("context") or "").strip()
        if ctx_raw:
            pivot = ctx_raw.split(",")[0].strip()
    ctx = build_template_context(
        domain=domain,
        host=host or "<DC>",
        user=pivot or "<user>",
        workspace=workspace,
        op_id=str(op.get("id") or ""),
    )
    ctx["DOMAIN"] = domain
    ctx["DC"] = host or "<DC>"
    return ctx


def _postex_command(op: dict[str, Any], workspace: str, ws_path: Path) -> str:
    """Map post-ex technique to the correct CLI — ``postex run`` is DLL hijack only."""
    from admapper.postex.templates import apply_postex_templates

    tech = str(op.get("technique") or "")
    op_id = str(op.get("id") or "postex-001")

    if tech in _POSTEX_RUN_TECHNIQUES:
        return f"admapper postex run --op {op_id} -w {workspace}"

    if tech == "dcsync":
        ctx = _postex_template_ctx(ws_path, workspace, op)
        user = ctx.get("user") or "<user>"
        host = ctx.get("host") or ctx.get("DC") or "<DC>"
        domain = ctx.get("domain") or ctx.get("DOMAIN") or workspace
        return f"secretsdump.py {domain}/{user}:<pass>@{host} -just-dc"

    if tech == "share_loot":
        return f"admapper loot -w {workspace}"

    if tech == "adminto":
        ctx = _postex_template_ctx(ws_path, workspace, op)
        host = ctx.get("host") or "<host>"
        return f"admapper winrm -H {host} -w {workspace}"

    for candidate in op.get("manual_commands") or []:
        text = str(candidate).strip()
        if text.startswith("admapper"):
            ctx = _postex_template_ctx(ws_path, workspace, op)
            return apply_postex_templates(text, ctx)
    if op.get("manual_commands"):
        ctx = _postex_template_ctx(ws_path, workspace, op)
        return apply_postex_templates(str(op["manual_commands"][0]).strip(), ctx)

    return f"admapper postex show -w {workspace}"


def pick_postex_action(ws_path: Path, workspace: str) -> dict[str, Any] | None:
    """Highest-value open post-ex opportunity from ``postex_ops.json``."""
    data = _load_json(ws_path / "postex_ops.json") or {}
    ops = list(data.get("opportunities") or [])
    if not ops:
        return None

    def sort_key(op: dict[str, Any]) -> tuple[int, str]:
        sev = _SEVERITY_RANK.get(str(op.get("severity") or "info"), 9)
        technique = str(op.get("technique") or "")
        if technique in _SKIP_POSTEX:
            sev += 10
        if op.get("dcsync_failed"):
            sev += 5
        return (sev, str(op.get("id") or ""))

    ops.sort(key=sort_key)
    op: dict[str, Any] | None = None
    for candidate in ops:
        if str(candidate.get("technique") or "") in _SKIP_POSTEX:
            continue
        op = candidate
        break
    if op is None:
        return None

    cmd = _postex_command(op, workspace, ws_path)

    target = str(op.get("target_host") or op.get("context") or "").strip()
    technique = str(op.get("technique") or "")
    return {
        "command": cmd,
        "headline": str(op.get("title") or technique or "Post-ex opportunity"),
        "technique": technique,
        "target": target,
        "reason": str(op.get("summary") or op.get("detail") or "").strip(),
        "impact": f"Post-ex · {op.get('severity', 'medium')} severity",
        "source": "postex",
        "op_id": str(op.get("id") or ""),
        "postex_runnable": technique in _POSTEX_RUN_TECHNIQUES,
    }


def build_next_action(
    ws_path: Path,
    *,
    workspace: str,
    objective: dict[str, Any],
    mission: dict[str, Any] | None,
    dashboard: dict[str, Any],
    effective_progress: dict[str, bool],
) -> dict[str, Any]:
    """Single next-step card for the dashboard (CLI + web share this logic)."""
    postex = pick_postex_action(ws_path, workspace)
    if postex and effective_progress.get("exploit"):
        return postex

    obj_cmd = str(objective.get("command") or "").strip()
    if obj_cmd:
        return {
            "command": obj_cmd,
            "headline": str(objective.get("headline") or "Attack path"),
            "technique": str(objective.get("technique") or ""),
            "target": str(objective.get("target") or ""),
            "reason": str(objective.get("headline") or objective.get("technique") or ""),
            "impact": "Privilege escalation via mapped graph edge",
            "source": "objective",
        }

    if mission:
        m_cmd = str(mission.get("command") or "").strip()
        if m_cmd:
            return {
                "command": m_cmd,
                "headline": str(mission.get("title") or mission.get("button") or "Mission"),
                "technique": str(mission.get("technique") or ""),
                "target": str(mission.get("target") or ""),
                "reason": str(mission.get("summary") or mission.get("reason") or ""),
                "impact": "Verified ACL / escalation mission",
                "source": "mission",
            }

    for act in dashboard.get("actions") or []:
        if act.get("required") and act.get("enabled"):
            action = str(act.get("action") or "")
            cmd_map = {
                "scan": f"admapper scan -H {workspace}",
                "enum": f"admapper enum users -w {workspace}",
                "run": f"admapper run -w {workspace} -u <user> -p '<pass>'",
                "acls": f"admapper acls -w {workspace}",
                "exploit": f"admapper exploit -w {workspace}",
            }
            return {
                "command": cmd_map.get(action, f"admapper {action} -w {workspace}"),
                "headline": str(act.get("button") or act.get("reason") or "Next phase"),
                "technique": action,
                "target": "",
                "reason": str(act.get("reason") or ""),
                "impact": "Unlocks the next operational phase",
                "source": "phase",
            }

    if not effective_progress.get("scan"):
        return {
            "command": f"admapper scan -H {workspace}",
            "headline": "Unauthenticated discovery",
            "technique": "scan",
            "target": workspace,
            "reason": "No recon data in workspace yet.",
            "impact": "Discovers domain, DC, and open AD ports.",
            "source": "phase",
        }
    if not effective_progress.get("enum_users"):
        return {
            "command": f"admapper enum users -w {workspace}",
            "headline": "User enumeration",
            "technique": "enum",
            "target": "",
            "reason": "Recon complete — enumerate domain accounts.",
            "impact": "Builds spray/roast target list.",
            "source": "phase",
        }
    if not effective_progress.get("loot") and effective_progress.get("enum_users"):
        return {
            "command": f"admapper loot -w {workspace}",
            "headline": "SMB share loot",
            "technique": "loot",
            "target": "",
            "reason": "Enumerate SYSVOL/Logs for credentials.",
            "impact": "May recover cleartext passwords from shares.",
            "source": "phase",
        }

    return {
        "command": f"admapper brief -w {workspace}",
        "headline": str(dashboard.get("stage_label") or "Review engagement"),
        "technique": "",
        "target": "",
        "reason": "Workspace has progress — review brief or pick a path in Attack Paths.",
        "impact": "Summarizes owned users, hashes, and next hops.",
        "source": "fallback",
    }
