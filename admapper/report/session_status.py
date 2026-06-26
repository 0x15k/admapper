from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from admapper.report.scenario import (
    count_credentials,
    infer_kill_chain_phase,
    list_artefact_status,
    resolve_next_command,
)
from admapper.support.output import print_info, print_success, print_table, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


def _dc_info(ws_path: Path, hosts: str | None) -> tuple[str, str]:
    from admapper.report.engagement import _load_json

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = hosts or ""
    dc_host = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", dc_ip))
            dc_host = str(host.get("hostname") or "")
            break
    if not dc_host and unauth.get("hosts"):
        first = unauth["hosts"][0]
        if not dc_ip:
            dc_ip = str(first.get("address", ""))
        dc_host = str(first.get("hostname") or "")
    return dc_ip or "-", dc_host or "sin PTR"


def build_session_status_lines(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    mode: str,
    owned_users: list[str] | None,
    pivot_user: str | None,
    hosts: str | None = None,
) -> list[str]:
    """Session Manager dashboard (AdStrike-style) as text lines."""
    owned = list(owned_users or [])
    pivot = pivot_user or (owned[-1] if owned else "(none)")
    domain_s = domain or "(no domain)"
    phase = infer_kill_chain_phase(ws_path, owned)
    dc_ip, dc_host = _dc_info(ws_path, hosts)
    valid, invalid = count_credentials(ws_path)
    next_cmd = resolve_next_command(
        ws_path,
        pivot=pivot,
        owned=owned,
        domain=domain_s if domain else "",
        workspace=workspace,
    )

    lines = [
        "═" * 56,
        "  SESSION MANAGER",
        "═" * 56,
        f"  Workspace : {workspace}",
        f"  Domain    : {domain_s}",
        f"  DC        : {dc_ip} ({dc_host})",
        f"  Mode      : {mode}",
        f"  Pivot     : {pivot}",
        f"  Owned     : {', '.join(owned) if owned else '(ninguno)'}",
        f"  Phase     : {phase}",
        f"  Creds     : {valid} valid / {invalid} invalid",
        "",
        "  Artefacts:",
    ]
    for label, present in list_artefact_status(ws_path):
        mark = "✓" if present else "·"
        lines.append(f"    {mark} {label}")

    lines.extend(
        [
            "",
            "  Next action:",
            f"    {next_cmd}",
            "═" * 56,
        ]
    )
    return lines


def print_session_status(session: Session) -> None:
    """Print Session Manager dashboard for active workspace."""
    if session.workspace is None:
        from admapper.support.output import print_error

        print_error("no active workspace — run: set workspace <name>")
        return

    ws = session.workspace
    ws_path = session.workspaces.path_for(ws.name)
    lines = build_session_status_lines(
        ws_path,
        workspace=ws.name,
        domain=ws.domain,
        mode=ws.mode.value,
        owned_users=list(ws.owned_users or []),
        pivot_user=ws.pivot_user,
        hosts=ws.hosts,
    )
    print_success("ADMapper session status")
    for line in lines:
        if line.startswith("    ") and (
            line.strip().startswith("admapper")
            or line.strip().startswith("start_auth")
            or line.strip().startswith("creds")
            or line.strip().startswith("acls")
        ):
            print_warning(line)
        elif line.strip().startswith("Next action"):
            print_info(line)
        else:
            print(line)

    valid, invalid = count_credentials(ws_path)
    print_table(
        "Credentials",
        ["valid", "invalid"],
        [[str(valid), str(invalid)]],
    )
