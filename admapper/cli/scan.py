from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.cli.commands import dispatch
from admapper.core.discovery import default_workspace_name, ensure_domain
from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.models.workspace import OperationMode
from admapper.recon.unauth import run_unauth_scan

if TYPE_CHECKING:
    from admapper.core.session import Session


def format_hosts_hint(ip: str, fqdn: str) -> str | None:
    """AdStrike auto-discovery: suggest /etc/hosts entry when DC FQDN is known."""
    ip = ip.strip()
    fqdn = fqdn.strip().rstrip(".")
    if not ip or not fqdn or fqdn in {"-", "sin PTR"}:
        return None
    return f"→ add to /etc/hosts: {ip}  {fqdn}"


def _load_unauth_report(ws_path: Path) -> dict:
    path = ws_path / "unauth_scan.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def print_scan_summary(session: Session) -> None:
    """Black-box summary after unauthenticated recon."""
    if session.workspace is None:
        return

    ws = session.workspace
    ws_path = session.workspaces.path_for(ws.name)
    report = _load_unauth_report(ws_path)

    domain = ws.domain or report.get("domain") or "-"
    dc_rows: list[list[str]] = []
    for host in report.get("hosts") or []:
        if host.get("is_domain_controller") or host.get("address") == ws.hosts:
            dc_rows.append(
                [
                    str(host.get("address", "-")),
                    str(host.get("hostname") or "-"),
                    ",".join(str(p) for p in host.get("open_ports") or []),
                    "yes" if host.get("is_domain_controller") else "",
                ]
            )
    if not dc_rows and ws.hosts:
        for host in report.get("hosts") or []:
            if str(host.get("address")) == ws.hosts:
                dc_rows.append(
                    [
                        str(host.get("address", "-")),
                        str(host.get("hostname") or "-"),
                        ",".join(str(p) for p in host.get("open_ports") or []),
                        "",
                    ]
                )

    print_success("Black-box recon complete")
    print_table(
        "Engagement",
        ["field", "value"],
        [
            ["workspace", ws.name],
            ["data", str(ws_path)],
            ["target", ws.hosts or "-"],
            ["domain", domain],
            ["mode", ws.mode.value],
        ],
    )
    if dc_rows:
        print_table("Domain controller", ["ip", "hostname", "ports", "dc"], dc_rows)
        for row in dc_rows:
            hint = format_hosts_hint(str(row[0]), str(row[1]))
            if hint:
                print_info(hint)
                break

    findings = report.get("findings") or []
    if findings:
        frows = [
            [
                str(f.get("severity", "")),
                str(f.get("title", "")),
                str(f.get("detail", ""))[:80],
            ]
            for f in findings[:12]
        ]
        print_table("Findings (top)", ["severity", "title", "detail"], frows)
        if len(findings) > 12:
            print_info(f"  … +{len(findings) - 12} more in findings.json")

    target = ws.hosts or "<ip>"
    wflag = f" -w {ws.name}" if ws.name else ""
    print_info("Siguiente:")
    print_info(
        f"  admapper run -H {target} -u <user> -p '<pass>'{wflag} --clock-skew '+7h'"
    )
    if domain and domain != "-":
        print_info(f"Optional override:  > set domain {domain}")
    print_warning("No credentials were used — workspace is recon-only until you add creds.")


def scan_engagement(
    session: Session,
    *,
    ip_dc: str,
    workspace: str | None = None,
    domain: str | None = None,
    mode: OperationMode = OperationMode.SEMI,
    sync_clock: bool = True,
) -> None:
    """
    Phase 0 black-box entry: only the DC IP is required.

    Creates/loads a workspace, runs unauthenticated recon, infers domain, prints summary.
    """
    ip = ip_dc.strip()
    if not ip:
        raise ValueError("DC IP is required")

    ws_name = workspace or default_workspace_name(ip)

    for line in (
        f"set workspace {ws_name}",
        f"set hosts {ip}",
        f"set mode {mode.value}",
    ):
        dispatch(session, line)

    if domain:
        dispatch(session, f"set domain {domain}")

    print_info(f"Black-box recon @ {ip} → workspace {ws_name}")
    run_unauth_scan(session)

    try:
        ensure_domain(session, announce=False)
    except ValueError:
        print_warning("domain not inferred — PTR/LDAP may be restricted; set domain manually if known")

    from admapper.creds.time_sync import ensure_dc_clock

    ws_path = (
        session.workspaces.path_for(session.workspace.name) if session.workspace else None
    )
    ensure_dc_clock(ip, enabled=sync_clock, ws_path=ws_path)

    print_scan_summary(session)

    if session.workspace is not None:
        session.persist_workspace()
