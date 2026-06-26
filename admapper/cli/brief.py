from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.cli.commands import dispatch
from admapper.core.output import print_info
from admapper.core.verbosity import is_verbose, print_phase
from admapper.creds.kerberos_skew import apply_clock_skew_option, ensure_workspace_skew
from admapper.report.engagement_map import print_engagement_map
from admapper.report.export import run_export
from admapper.report.scenario import print_scenario_report

if TYPE_CHECKING:
    from admapper.core.session import Session

# Light: loot + ACLs + next hop. Deep adds paths/adcs/postex.
_PIPELINE_LIGHT = ("exploit", "acls", "escalate")
_PIPELINE_DEEP = ("exploit", "acls", "paths", "adcs", "postex", "escalate")
_PIPELINE_AUTO = ("exploit", "acls", "postex", "escalate")


def _best_cred_per_user(credentials: list[dict]) -> dict[str, dict]:
    best: dict[str, dict] = {}
    for cred in credentials:
        user = str(cred.get("username", "")).lower()
        if not user:
            continue
        prev = best.get(user)
        if prev is None:
            best[user] = cred
            continue
        if str(cred.get("status")) == "valid" and str(prev.get("status")) != "valid":
            best[user] = cred
    return best


def _needs_exploit_refresh(ws_path: Path) -> bool:
    """Skip redundant exploit rounds when loot creds and gMSA hashes are settled."""
    if is_verbose():
        return True
    manifest_path = ws_path / "loot_manifest.json"
    cred_path = ws_path / "credentials.json"
    if not manifest_path.is_file():
        return True
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cred_data = json.loads(cred_path.read_text(encoding="utf-8")) if cred_path.is_file() else {}
    best = _best_cred_per_user(cred_data.get("credentials") or [])
    for item in manifest.get("parsed_credentials") or []:
        user = str(item.get("username", "")).lower()
        match = best.get(user)
        if match is None or str(match.get("status")) != "valid":
            return True
    acl_path = ws_path / "acl_findings.json"
    if not acl_path.is_file():
        return True
    acl = json.loads(acl_path.read_text(encoding="utf-8"))
    log_path = ws_path / "exploit_log.json"
    log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.is_file() else {}
    known_hashes = {str(e.get("account", "")).lower() for e in log.get("new_hashes") or []}
    for finding in acl.get("findings") or []:
        right = str(finding.get("right", "")).lower()
        target = str(finding.get("target_name", "")).lower()
        if right in {"genericwrite", "readgmsapassword"} and (
            "msa_" in target or target.endswith("$")
        ):
            account = target if target.endswith("$") else f"{target}$"
            if account.lower() not in known_hashes:
                return True
    return False


def run_brief(
    session: Session,
    *,
    clock_skew: str | None = None,
    sync_clock: bool = True,
    refresh: bool = True,
    deep: bool = False,
    auto: bool = False,
) -> None:
    """Refresh intel and display engagement map (compact by default)."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.core.dashboard_mode import effective_sync_clock

    apply_clock_skew_option(clock_skew)
    sync_clock = effective_sync_clock(sync_clock)

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)
    ensure_workspace_skew(ws_path)

    if auto:
        from admapper import __version__
        from admapper.engage.auto import prepare_auto

        print_info(f"admapper {__version__} — --auto mode")
        prepare_auto(session)

    if refresh:
        if auto:
            pipeline = _PIPELINE_AUTO
        else:
            pipeline = _PIPELINE_DEEP if deep else _PIPELINE_LIGHT
        print_phase(f"analyst — {len(pipeline)} modules …")
        for cmd in pipeline:
            try:
                if cmd == "exploit":
                    if not _needs_exploit_refresh(ws_path):
                        print_info("exploit skipped — no new creds or pending gMSA")
                        continue
                    from admapper.exploit.engine import run_exploit_engagement

                    max_rounds = 5 if auto else (3 if is_verbose() else 1)
                    run_exploit_engagement(
                        session,
                        max_rounds=max_rounds,
                        sync_clock=sync_clock,
                    )
                elif auto and cmd == "postex":
                    from admapper.engage.auto import run_auto_postex_scan

                    run_auto_postex_scan(session)
                else:
                    dispatch(session, cmd)
            except (ValueError, RuntimeError) as exc:
                print_info(f"  {cmd}: {exc}")

    if auto:
        from admapper.engage.auto import finalize_auto

        finalize_auto(session)

    from admapper.analysis.user_match import refresh_workspace_intel

    refresh_workspace_intel(ws_path)

    run_export(session, quiet=True)
    print_engagement_map(
        ws_path,
        workspace=ws_name,
        domain=session.workspace.domain,
        owned_users=list(session.workspace.owned_users or []),
        pivot_user=session.workspace.pivot_user,
    )
    from admapper.graph.web import write_attack_graph_html

    graph_html = write_attack_graph_html(
        ws_path,
        workspace=ws_name,
        domain=session.workspace.domain,
        owned_users=list(session.workspace.owned_users or []),
        pivot_user=session.workspace.pivot_user,
    )
    if is_verbose():
        print_info(f"attack graph (web) → file://{graph_html.resolve()}")
    else:
        print_info(f"grafo → file://{graph_html.resolve()}")
    if is_verbose():
        from admapper.graph.show import print_attack_graph

        print_attack_graph(
            ws_path,
            domain=session.workspace.domain,
            pivot_user=session.workspace.pivot_user,
            owned_users=list(session.workspace.owned_users or []),
        )
    if is_verbose():
        print_scenario_report(
            ws_path,
            workspace=ws_name,
            domain=session.workspace.domain,
            owned_users=list(session.workspace.owned_users or []),
            pivot_user=session.workspace.pivot_user,
        )
