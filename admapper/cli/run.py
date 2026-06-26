from __future__ import annotations

if __name__ == "__main__":
    raise SystemExit(
        "Do not run this file directly.\n\n"
        "  pip install -e \".[dev]\"\n"
        "  admapper run -H <ip> -u <user> -p '<pass>'\n\n"
        "Kali (PEP 668 — use venv, not system pip):\n"
        "  bash scripts/kali-setup.sh /compartido/admapper\n"
        "  source ~/admapper-venv/bin/activate\n\n"
        "Or without installing:\n"
        "  python3 -m admapper.cli.main run -H <ip> ..."
    )

import json
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.cli.commands import dispatch
from admapper.support.discovery import default_workspace_name, ensure_domain
from admapper.support.output import print_info
from admapper.support.session import Session


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def run_engagement(
    session: Session,
    *,
    host: str,
    workspace: str | None = None,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    full: bool = False,
    minimal: bool = False,
    clock_skew: str | None = None,
    sync_clock: bool = True,
    sync_hosts: bool = True,
    verbose: bool = False,
    auto: bool = False,
) -> None:
    """Non-interactive engagement — con creds ejecuta analyst por defecto."""
    from admapper.support.dashboard_mode import effective_sync_clock, effective_sync_hosts
    from admapper.kerberos.skew import apply_clock_skew_option
    from admapper.kerberos.time_sync import ensure_dc_clock

    from admapper.support.verbosity import set_verbose

    apply_clock_skew_option(clock_skew)
    set_verbose(verbose)
    sync_clock = effective_sync_clock(sync_clock)
    sync_hosts = effective_sync_hosts(sync_hosts)

    ws_name = workspace or default_workspace_name(host)

    for line in (
        f"set workspace {ws_name}",
        f"set hosts {host}",
        "set mode auto",
    ):
        dispatch(session, line)

    if domain:
        dispatch(session, f"set domain {domain}")

    if not username and not password:
        from admapper.cli.scan import print_scan_summary

        dispatch(session, "start_unauth")
        try:
            ensure_domain(session)
        except ValueError as exc:
            print_info(str(exc))
        ws_path = (
            session.workspaces.path_for(session.workspace.name)
            if session.workspace
            else None
        )
        ensure_dc_clock(host, enabled=sync_clock, ws_path=ws_path)
        print_scan_summary(session, sync_hosts=sync_hosts)
        if session.workspace is not None:
            session.persist_workspace()
        return

    ws_path = (
        session.workspaces.path_for(session.workspace.name)
        if session.workspace
        else None
    )
    unauth_cache = _load_json(ws_path / "unauth_scan.json") if ws_path else None
    unauth_has_domain = bool(unauth_cache and unauth_cache.get("domain"))
    unauth_cached = bool(ws_path and (ws_path / "unauth_scan.json").is_file() and unauth_has_domain)
    if unauth_cached:
        print_info("unauth_scan.json cached with domain — skipping Phase 1 recon")
    else:
        dispatch(session, "start_unauth")

    try:
        ensure_domain(session)
    except ValueError as exc:
        print_info(str(exc))

    ensure_dc_clock(host, enabled=sync_clock, ws_path=ws_path)

    from admapper.cli.scan import sync_hosts_from_session

    sync_hosts_from_session(session, enabled=sync_hosts)

    if not session.workspace or not session.workspace.domain:
        from admapper.recon.ldap_probe import discover_domain_from_bind
        from admapper.kerberos.skew import ensure_workspace_skew

        if ws_path:
            ensure_workspace_skew(ws_path)
        inferred = discover_domain_from_bind(
            host,
            username,
            password,
            domain_hint=domain,
        )
        if inferred:
            session.set_domain(inferred)
            from admapper.support.output import print_success

            print_success(f"domain inferred from LDAP bind: {inferred}")

    dispatch(session, f"creds add {username} {password}")

    creds = session.credentials.list() if session.credentials else []
    if creds:
        dispatch(session, f"creds verify {creds[-1].id}")
        dispatch(session, "start_auth")

    ran_analyst = False
    if full:
        try:
            ensure_domain(session, announce=False)
        except ValueError:
            pass
        if session.workspace and session.workspace.domain:
            for cmd in (
                "enum users",
                "paths",
                "acls",
                "kerberos",
                "adcs",
                "coerce",
                "postex",
                "escalate",
                "mssql",
                "cves",
                "exploit",
                "export",
            ):
                dispatch(session, cmd)
    elif not minimal:
        from admapper.cli.brief import run_brief

        run_brief(
            session,
            clock_skew=clock_skew,
            sync_clock=sync_clock,
            refresh=True,
            auto=auto,
        )
        ran_analyst = True
    else:
        dispatch(session, "show")

    if session.workspace is not None:
        session.persist_workspace()
        if not ran_analyst and not full:
            ws_path = session.workspaces.path_for(session.workspace.name)
            print_info(f"workspace: {ws_path}")
