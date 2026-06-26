from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.cli.commands import dispatch
from admapper.support.discovery import default_workspace_name, ensure_domain
from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.models.workspace import OperationMode
from admapper.recon.unauth import run_unauth_scan

if TYPE_CHECKING:
    from admapper.support.session import Session


_HOSTS_POLL_INTERVAL = 3   # seconds between checks
_HOSTS_POLL_MAX = 20       # max attempts (~60s total)


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


def sync_hosts_from_session(session: Session, *, enabled: bool = True) -> None:
    """Update /etc/hosts from unauth scan DC row when FQDN is known."""
    if not enabled or session.workspace is None:
        return
    ws_path = session.workspaces.path_for(session.workspace.name)
    report = _load_unauth_report(ws_path)
    for host in report.get("hosts") or []:
        if host.get("is_domain_controller") or str(host.get("address")) == session.workspace.hosts:
            fqdn = str(host.get("hostname") or "")
            ip = str(host.get("address") or session.workspace.hosts or "")
            if ip and fqdn and fqdn != "-":
                _sync_dc_hosts_entry(ip, fqdn, sync_hosts=True)
                return


def _sync_dc_hosts_entry(ip: str, fqdn: str, *, sync_hosts: bool) -> None:
    if not sync_hosts:
        hint = format_hosts_hint(ip, fqdn)
        if hint:
            print_info(hint)
        return

    from admapper.support.system_hosts import (
        HostsSyncStatus,
        ensure_system_hosts_entry,
        format_hosts_sync_message,
        hosts_entry_exists,
    )

    # 1) Try automatic write (sudo -n, non-interactive)
    result = ensure_system_hosts_entry(ip, fqdn)
    message = format_hosts_sync_message(result)

    if result.status in {HostsSyncStatus.PRESENT, HostsSyncStatus.ADDED, HostsSyncStatus.UPDATED}:
        print_success(message)
        return

    if result.status != HostsSyncStatus.FAILED:
        print_info(message)
        return

    # 2) Auto-write failed — show command and poll for manual entry
    print_warning("/etc/hosts needs update. Run this in another terminal:")
    print_info("")
    print_info(f"  sudo sh -c 'echo \"{ip}  {fqdn}\" >> /etc/hosts'")
    print_info("")
    print_info(f"Waiting for /etc/hosts entry... (Ctrl+C to skip, checking every {_HOSTS_POLL_INTERVAL}s)")

    try:
        for attempt in range(1, _HOSTS_POLL_MAX + 1):
            time.sleep(_HOSTS_POLL_INTERVAL)
            if hosts_entry_exists(ip, fqdn):
                print_success(f"/etc/hosts updated! {ip}  {fqdn}")
                return
            print_info(f"  checking... ({attempt}/{_HOSTS_POLL_MAX})")
    except KeyboardInterrupt:
        print_warning("skipped — Kerberos may fail without /etc/hosts entry")
        return

    print_warning(f"timeout after {_HOSTS_POLL_MAX * _HOSTS_POLL_INTERVAL}s — continuing without /etc/hosts")


def print_scan_summary(session: Session, *, sync_hosts: bool = True) -> None:
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
            _sync_dc_hosts_entry(str(row[0]), str(row[1]), sync_hosts=sync_hosts)
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


def sync_dc_engagement(
    session: Session,
    *,
    ip_dc: str,
    workspace: str | None = None,
    sync_hosts: bool = True,
) -> None:
    """One-shot local prep: sync clock to DC and optional /etc/hosts (requires sudo)."""
    ip = ip_dc.strip()
    if not ip:
        raise ValueError("DC IP is required")

    ws_name = workspace or default_workspace_name(ip)
    session.select_workspace(ws_name, create=True)
    dispatch(session, f"set hosts {ip}")
    session.persist_workspace()

    from admapper.support.output import print_info, print_success
    from admapper.kerberos.time_sync import ensure_dc_clock

    ws_path = session.workspaces.path_for(ws_name)
    print_info(f"sync-dc @ {ip} → workspace {ws_name}")
    if ensure_dc_clock(ip, enabled=True, ws_path=ws_path, force=True):
        print_success("clock synchronized with the DC")
    else:
        print_info("clock: use libfaketime if Kerberos still fails")

    print_scan_summary(session, sync_hosts=sync_hosts)
    session.persist_workspace()


def scan_engagement(
    session: Session,
    *,
    ip_dc: str,
    workspace: str | None = None,
    domain: str | None = None,
    mode: OperationMode = OperationMode.SEMI,
    sync_clock: bool = True,
    sync_hosts: bool = True,
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

    from admapper.support.dashboard_mode import effective_sync_clock, effective_sync_hosts
    from admapper.kerberos.time_sync import ensure_dc_clock

    sync_clock = effective_sync_clock(sync_clock)
    sync_hosts = effective_sync_hosts(sync_hosts)
    ws_path = (
        session.workspaces.path_for(session.workspace.name) if session.workspace else None
    )
    ensure_dc_clock(ip, enabled=sync_clock, ws_path=ws_path)

    print_scan_summary(session, sync_hosts=sync_hosts)

    if session.workspace is not None:
        session.persist_workspace()
