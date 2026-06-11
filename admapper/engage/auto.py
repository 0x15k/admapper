from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.core.graph import GraphStore
from admapper.core.output import print_info, print_success
from admapper.core.owned import is_valid_owned_username
from admapper.core.provenance import Tool, print_step
from admapper.creds.common import collect_gained_hashes
from admapper.escalate.analyze import get_escalation_state, run_escalate_analysis, run_escalate_exec
from admapper.models.escalation import EscalationEdge
from admapper.models.workspace import OperationMode

if TYPE_CHECKING:
    from admapper.core.session import Session

_WIRED_EDGES = {
    ("postex", "dll_hijack_scheduled_task"),
    ("wsus", "wsus_cert_chain"),
    ("adcs", "template_enrollment"),
}


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _lightweight_mark_owned(session: Session, username: str) -> bool:
    """Append owned + graph mark without pivot refresh. Returns True if newly marked."""
    if session.workspace is None or not is_valid_owned_username(username):
        return False
    owned_lower = {u.lower() for u in session.workspace.owned_users}
    if username.lower() in owned_lower:
        return False
    session.workspace.owned_users.append(username)
    session.persist_workspace()
    domain = session.workspace.domain
    if domain:
        GraphStore(session.workspaces, session.workspace.name).mark_user_owned(domain, username)
    print_success(f"auto owned: {username}")
    return True


def sync_owned_from_intel(session: Session) -> list[str]:
    """Auto-mark users from exploit_log new_hashes and new_users (lightweight)."""
    if session.workspace is None:
        return []
    ws_path = session.workspaces.path_for(session.workspace.name)
    log = _load_json(ws_path / "exploit_log.json") or {}
    marked: list[str] = []
    for item in log.get("new_hashes") or []:
        account = str(item.get("account") or "").strip()
        if account and _lightweight_mark_owned(session, account):
            marked.append(account)
    for user in log.get("new_users") or []:
        name = str(user).strip()
        if name and _lightweight_mark_owned(session, name):
            marked.append(name)
    return marked


from admapper.escalate.pivot import pick_best_pivot


def auto_set_pivot(session: Session) -> str | None:
    """Set pivot: lateral human after machine hash, else gMSA, else last human."""
    if session.workspace is None:
        return None
    ws_path = session.workspaces.path_for(session.workspace.name)
    owned = list(session.workspace.owned_users or [])
    candidate = pick_best_pivot(owned, ws_path=ws_path)

    if not candidate:
        return None
    if session.workspace.pivot_user != candidate:
        session.workspace.pivot_user = candidate
        session.persist_workspace()
        print_info(f"auto pivot → {candidate}")
    return candidate


def _postex_scan_stale(ws_path: Path) -> bool:
    scan_path = ws_path / "postex_scan.json"
    if not scan_path.is_file():
        return True
    log_path = ws_path / "exploit_log.json"
    if not log_path.is_file():
        return False
    try:
        return log_path.stat().st_mtime > scan_path.stat().st_mtime
    except OSError:
        return False


def _postex_ops_stale(ws_path: Path) -> bool:
    ops_path = ws_path / "postex_ops.json"
    if not ops_path.is_file():
        return True
    scan_path = ws_path / "postex_scan.json"
    if not scan_path.is_file():
        return False
    try:
        return scan_path.stat().st_mtime > ops_path.stat().st_mtime
    except OSError:
        return False


def run_auto_postex_scan(session: Session) -> bool:
    """Remote task hijack scan when machine hashes exist; rebuild postex_ops.json."""
    if session.workspace is None:
        return False
    ws_path = session.workspaces.path_for(session.workspace.name)
    hashes = collect_gained_hashes(ws_path)
    if not hashes:
        return False

    scan_stale = _postex_scan_stale(ws_path)
    ops_stale = _postex_ops_stale(ws_path)
    if not scan_stale and not ops_stale:
        return False

    ws_name = session.workspace.name
    from admapper.postex.analyze import run_postex_analysis
    from admapper.postex.remote_scan import run_remote_task_hijack_scan

    if scan_stale:
        print_step(
            "postex remote scan (machine hash)",
            source=Tool.ADMAPPER,
            manual=f"admapper postex scan -w {ws_name}",
        )
        run_remote_task_hijack_scan(session)

    if scan_stale or ops_stale:
        run_postex_analysis(session)
        return True
    return False


def _is_wired_edge(edge: dict[str, Any]) -> bool:
    module = str(edge.get("module") or "")
    technique = str(edge.get("technique") or "")
    return (module, technique) in _WIRED_EDGES


def _edge_from_dict(raw: dict[str, Any]) -> EscalationEdge:
    return EscalationEdge(
        technique=str(raw.get("technique") or ""),
        module=str(raw.get("module") or ""),
        title=str(raw.get("title") or ""),
        severity=str(raw.get("severity") or "medium"),
        summary=str(raw.get("summary") or ""),
        target=str(raw.get("target") or ""),
        op_id=str(raw.get("op_id") or ""),
        ready=bool(raw.get("ready", True)),
        target_owned=bool(raw.get("target_owned", False)),
        manual_commands=list(raw.get("manual_commands") or []),
        mitre_id=str(raw.get("mitre_id") or ""),
    )


def _pick_wired_next(state: dict[str, Any] | None) -> dict[str, Any] | None:
    """Best ready wired edge (same ranking as escalate NEXT)."""
    from admapper.escalate.edges import sort_edges

    if not state:
        return None
    raws: list[dict[str, Any]] = list(state.get("edges") or [])
    if not raws:
        return None
    ranked = sort_edges([_edge_from_dict(raw) for raw in raws])
    raw_by_key = {
        (str(r.get("module") or ""), str(r.get("technique") or ""), str(r.get("target") or "").lower()): r
        for r in raws
    }
    for edge in ranked:
        if edge.technique == "member_of":
            continue
        if not edge.ready or edge.target_owned:
            continue
        key = (edge.module, edge.technique, edge.target.lower())
        raw = raw_by_key.get(key)
        if raw and _is_wired_edge(raw):
            return raw
    return None


def run_auto_exec(session: Session, *, max_steps: int = 4) -> int:
    """Chain wired escalation steps (postex / wsus / adcs) up to max_steps."""
    steps = 0
    for _ in range(max_steps):
        sync_owned_from_intel(session)
        auto_set_pivot(session)
        run_escalate_analysis(session)
        state = get_escalation_state(session)
        edge = _pick_wired_next(state)
        if edge is None:
            break
        module = edge.get("module", "")
        technique = edge.get("technique", "")
        target = edge.get("target", "")
        print_step(
            f"auto exec: {module}/{technique} → {target}",
            source=Tool.ADMAPPER,
        )
        try:
            run_escalate_exec(session, op_id=str(edge.get("op_id") or "") or None)
        except (ValueError, RuntimeError) as exc:
            print_info(f"auto exec stop — {exc}")
            break
        steps += 1
    return steps


def prepare_auto(session: Session) -> None:
    """Enable auto mode and sync owned/pivot from intel."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    session.workspace.mode = OperationMode.AUTO
    session.persist_workspace()
    sync_owned_from_intel(session)
    auto_set_pivot(session)


def finalize_auto(session: Session) -> None:
    """Post-pipeline: pivot to best account, run wired steps (incl. postex deploy/shell)."""
    if session.workspace is None:
        return
    sync_owned_from_intel(session)
    auto_set_pivot(session)
    run_auto_exec(session, max_steps=4)
    sync_owned_from_intel(session)
    auto_set_pivot(session)
    run_escalate_analysis(session)


def finalize_postex_shell(
    session: Session,
    *,
    username: str,
    probe_output: str = "",
    auto_chain: bool | None = None,
) -> None:
    """Mark shell user owned, refresh escalation, optionally chain wired next steps."""
    if session.workspace is None:
        return
    from admapper.escalate.analyze import mark_user_owned, record_escalation_step

    if (not username or username == "unknown") and probe_output.strip():
        from admapper.postex.runner import parse_shell_username

        username = parse_shell_username(probe_output)
    if not username or username == "unknown":
        return

    mark_user_owned(session, username, refresh=True)
    record_escalation_step(
        session,
        action="dll_hijack_shell",
        detail=f"postex shell → {username}",
    )
    session.workspace.pivot_user = username
    session.persist_workspace()
    run_escalate_analysis(session, pivot_user=username)

    chain = auto_chain
    if chain is None:
        chain = session.workspace.mode == OperationMode.AUTO
    if chain:
        run_auto_exec(session, max_steps=4)
        sync_owned_from_intel(session)
        auto_set_pivot(session)
        run_escalate_analysis(session)
