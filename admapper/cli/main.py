from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from admapper import __version__
from admapper.cli.run import run_engagement
from admapper.cli.shell import run_shell
from admapper.core.paths import WORKSPACES_ENV_VAR, set_cli_workspaces_root
from admapper.core.session import Session

app = typer.Typer(
    name="admapper",
    help="ADMapper — modular Active Directory pentesting CLI",
    no_args_is_help=False,
    add_completion=False,
)


def _print_version_and_exit(show: bool) -> bool:
    if show:
        typer.echo(__version__)
        raise typer.Exit()
    return show


@app.callback(invoke_without_command=True)
def _global_options(
    ctx: typer.Context,
    show_version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_print_version_and_exit,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = False,
    workspaces_root: Annotated[
        str | None,
        typer.Option(
            "--workspaces-root",
            "-O",
            envvar=WORKSPACES_ENV_VAR,
            help="Engagement data directory (default: ~/.admapper/workspaces)",
        ),
    ] = None,
    ip_dc: Annotated[
        str | None,
        typer.Option(
            "--ip-dc",
            help="DC IP only — black-box recon (no credentials). Same as: admapper scan --ip-dc <ip>",
        ),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored console output",
        ),
    ] = False,
) -> None:
    if no_color:
        from admapper.core.output import set_no_color
        set_no_color(True)
    set_cli_workspaces_root(Path(workspaces_root) if workspaces_root else None)
    if ctx.invoked_subcommand is None and not ip_dc:
        from admapper.cli.banner import print_workflow_banner

        print_workflow_banner()
        raise typer.Exit()
    if ctx.invoked_subcommand is None and ip_dc:
        from admapper.cli.scan import scan_engagement

        session = Session.bootstrap()
        try:
            scan_engagement(session, ip_dc=ip_dc, sync_clock=True)
        except (ValueError, RuntimeError) as exc:
            from admapper.core.output import print_error

            print_error(str(exc))
            raise typer.Exit(code=1) from exc
        raise typer.Exit()

postex_app = typer.Typer(
    help="Post-exploitation playbook (lateral, DLL hijack scan, dumps)",
    no_args_is_help=False,
)
app.add_typer(postex_app, name="postex")
app.add_typer(postex_app, name="px", hidden=True)


def _session_with_workspace(
    workspace: str | None = None,
    host: str | None = None,
    domain: str | None = None,
) -> Session:
    from admapper.core.discovery import default_workspace_name
    from admapper.core.output import print_error

    session = Session.bootstrap()
    if workspace:
        try:
            session.select_workspace(workspace, create=False)
        except FileNotFoundError as exc:
            hint = ""
            ws_hint = default_workspace_name(workspace)
            if ws_hint != workspace and session.workspaces.exists(ws_hint):
                hint = f" — did you mean '{ws_hint}'?"
            print_error(f"{exc}{hint}")
            raise typer.Exit(code=1) from None
        except ValueError as exc:
            print_error(str(exc))
            raise typer.Exit(code=1) from None
    elif host:
        ws_name = default_workspace_name(host)
        session.select_workspace(ws_name, create=False)
    elif domain:
        session.select_workspace(domain, create=False)

    if session.workspace is None:
        print_error("no active workspace — use: admapper run -H <ip> ... or specify -w <name> / -H <ip>")
        raise typer.Exit(code=1)
    return session


@postex_app.callback(invoke_without_command=True)
def postex_main(
    ctx: typer.Context,
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: active workspace)"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output pure JSON format"),
    ] = False,
) -> None:
    """Build post-ex playbook from workspace intel (loot hints + optional postex_scan.json)."""
    if ctx.invoked_subcommand is not None:
        return
    from admapper.core.output import print_error
    from admapper.postex.analyze import run_postex_analysis

    session = _session_with_workspace(workspace, host=host, domain=domain)
    try:
        res = run_postex_analysis(session, quiet=json_output)
        if json_output:
            import json
            from pathlib import Path
            if res.output_path and Path(res.output_path).is_file():
                typer.echo(Path(res.output_path).read_text(encoding="utf-8").strip())
            else:
                typer.echo(json.dumps([o.to_dict() for o in res.opportunities], indent=2))
    except (ValueError, RuntimeError) as exc:
        if json_output:
            import json
            typer.echo(json.dumps({"error": str(exc)}, indent=2))
        else:
            print_error(str(exc))
        raise typer.Exit(code=1) from exc


@postex_app.command("scan")
def postex_scan(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: active workspace)"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="WinRM target (default: gMSA/computer host from hash)"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
) -> None:
    """Remote WinRM scan: COM scheduled tasks + DLL hijack detection from loot intel."""
    from admapper.core.output import print_error
    from admapper.postex.analyze import run_postex_analysis

    session = _session_with_workspace(workspace, domain=domain)
    try:
        run_postex_analysis(session, remote_scan=True, remote_host=host)
    except (ValueError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


escalate_app = typer.Typer(help="Marcar owned, pivot y siguiente hop de escalada")
app.add_typer(escalate_app, name="escalate")
app.add_typer(escalate_app, name="esc", hidden=True)


@escalate_app.callback(invoke_without_command=True)
def escalate_main(
    ctx: typer.Context,
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output pure JSON format"),
    ] = False,
) -> None:
    """Muestra estado de escalada (siguiente hop)."""
    if ctx.invoked_subcommand is not None:
        return
    escalate_show(workspace=workspace, host=host, domain=domain, json_output=json_output)


@escalate_app.command("show")
def escalate_show(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output pure JSON format"),
    ] = False,
) -> None:
    """Muestra estado de escalada (siguiente hop)."""
    from admapper.escalate.analyze import run_escalate_analysis
    from admapper.core.output import print_error

    session = _session_with_workspace(workspace, host=host, domain=domain)
    try:
        state = run_escalate_analysis(session, quiet=json_output)
        if json_output:
            import json
            typer.echo(json.dumps(state.to_dict(), indent=2, sort_keys=True))
    except (ValueError, RuntimeError) as exc:
        if json_output:
            import json
            typer.echo(json.dumps({"error": str(exc)}, indent=2))
        else:
            print_error(str(exc))
        raise typer.Exit(code=1) from exc


@escalate_app.command("mark")
def escalate_mark(
    user: Annotated[str, typer.Argument(help="User or machine account (e.g. msa_health$)")],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
    no_refresh: Annotated[
        bool,
        typer.Option("--no-refresh", help="Do not re-run analysis after marking"),
    ] = False,
) -> None:
    """Mark a user as owned and set them as the active pivot."""
    from admapper.core.output import print_error
    from admapper.escalate.analyze import mark_user_owned

    session = _session_with_workspace(workspace, host=host, domain=domain)
    try:
        mark_user_owned(session, user, refresh=not no_refresh)
    except (ValueError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@escalate_app.command("pivot")
def escalate_pivot(
    user: Annotated[str, typer.Argument(help="New pivot")],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
) -> None:
    """Change the active pivot without adding the user to owned."""
    from admapper.core.output import print_error
    from admapper.escalate.analyze import run_escalate_analysis, set_pivot_user

    session = _session_with_workspace(workspace, host=host, domain=domain)
    try:
        set_pivot_user(session, user)
        run_escalate_analysis(session, pivot_user=user)
    except (ValueError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@postex_app.command("show")
def postex_show(
    op_id: Annotated[str, typer.Argument(help="Opportunity id from postex_ops.json (e.g. postex-010)")],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: active workspace)"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output pure JSON format"),
    ] = False,
) -> None:
    """Show one post-ex opportunity with manual commands."""
    from admapper.core.output import print_error, print_info
    from admapper.postex.analyze import get_postex_op
    from admapper.postex.render import print_postex_detail

    session = _session_with_workspace(workspace, host=host, domain=domain)
    detail = get_postex_op(session, op_id)
    if detail is None:
        if json_output:
            import json
            typer.echo(json.dumps({"error": f"post-ex opportunity not found: {op_id}"}, indent=2))
        else:
            print_error(f"post-ex opportunity not found: {op_id} — run: admapper postex -w <workspace>")
            path = session.workspaces.path_for(session.workspace.name) / "postex_ops.json"
            if path.is_file():
                import json

                data = json.loads(path.read_text(encoding="utf-8"))
                ids = [str(o.get("id", "")) for o in data.get("opportunities") or [] if o.get("id")]
                if ids:
                    print_info(f"Available ids: {', '.join(ids)}")
        raise typer.Exit(code=1)
    if json_output:
        import json
        typer.echo(json.dumps(detail, indent=2))
    else:
        print_postex_detail(detail)


@postex_app.command("deploy")
def postex_deploy(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: active workspace)"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
    op_id: Annotated[
        str | None,
        typer.Option("--op", help="Opportunity id (e.g. postex-010); default: scan finding"),
    ] = None,
    cred_id: Annotated[
        str | None,
        typer.Option("--cred-id", help="Credential id override"),
    ] = None,
    lhost: Annotated[
        str | None,
        typer.Option("--lhost", help="Callback IP (default: auto-detect VPN utun/tun)"),
    ] = None,
    lport: Annotated[int, typer.Option("--lport", help="Callback port")] = 4444,
    payload: Annotated[
        str | None,
        typer.Option("--payload", help="Path to existing DLL (skips msfvenom)"),
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Build payload only, no upload")] = False,
) -> None:
    """Deploy scheduled-task DLL hijack payload from postex_scan.json intel."""
    from pathlib import Path

    from admapper.core.output import print_error
    from admapper.postex.deploy import deploy_dll_hijack

    session = _session_with_workspace(workspace, host=host, domain=domain)
    try:
        deploy_dll_hijack(
            session,
            op_id=op_id,
            cred_id=cred_id,
            lhost=lhost,
            lport=lport,
            payload_dll=Path(payload) if payload else None,
            dry_run=dry_run,
        )
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@postex_app.command("run")
def postex_run(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: active workspace)"),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", "-H", help="Target IP or CIDR"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint"),
    ] = None,
    op_id: Annotated[
        str | None,
        typer.Option("--op", help="Opportunity id (e.g. postex-010)"),
    ] = None,
    cred_id: Annotated[
        str | None,
        typer.Option("--cred-id", help="Credential id override"),
    ] = None,
    lhost: Annotated[
        str | None,
        typer.Option("--lhost", help="Callback IP (default: auto-detect VPN utun/tun)"),
    ] = None,
    lport: Annotated[int, typer.Option("--lport", help="Callback port")] = 4444,
    payload: Annotated[
        str | None,
        typer.Option("--payload", help="Path to existing DLL (skips msfvenom)"),
    ] = None,
    wait: Annotated[int, typer.Option("--wait", help="Seconds to poll monitor.log after deploy")] = 180,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Plan only")] = False,
    use_ncat: Annotated[bool, typer.Option("--use-ncat", help="Use external ncat instead of built-in listener")] = False,
    no_listener: Annotated[bool, typer.Option("--no-listener", help="Skip built-in listener")] = False,
    arch: Annotated[
        str | None,
        typer.Option("--arch", help="Payload arch: x86 or x64 (default: auto from PE/monitor.log)"),
    ] = None,
    mode: Annotated[
        str,
        typer.Option("--mode", help="shell (reverse shell) or enroll (AD CS cert via hijack)"),
    ] = "shell",
    auto_chain: Annotated[
        bool,
        typer.Option(
            "--auto",
            help="After shell: mark owned + chain wired next step (escalate exec)",
        ),
    ] = False,
) -> None:
    """Auto: VPN IP + msfvenom + listener + deploy + wait for reverse shell."""
    from pathlib import Path

    from admapper.core.output import print_error
    from admapper.postex.pe_arch import normalize_arch
    from admapper.postex.payload import PayloadMode
    from admapper.postex.runner import run_dll_hijack

    session = _session_with_workspace(workspace, host=host, domain=domain)
    payload_arch = normalize_arch(arch) if arch else None
    payload_mode: PayloadMode = "enroll" if mode.lower() == "enroll" else "shell"
    try:
        run_dll_hijack(
            session,
            op_id=op_id,
            cred_id=cred_id,
            lhost=lhost,
            lport=lport,
            payload_dll=Path(payload) if payload else None,
            wait_seconds=wait,
            dry_run=dry_run,
            use_ncat=use_ncat,
            no_listener=no_listener or payload_mode == "enroll",
            arch=payload_arch,
            payload_mode=payload_mode,
            auto_chain=auto_chain,
        )
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@app.command()
def start() -> None:
    """Open the interactive ADMapper shell."""
    run_shell()


@app.command()
def scan(
    ip_dc: Annotated[
        str,
        typer.Option(
            "--ip-dc",
            "-H",
            "--host",
            help="Domain controller IP (only input required for black-box recon)",
        ),
    ],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: derived from IP)"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain hint if DNS/LDAP inference fails"),
    ] = None,
    no_sync: Annotated[
        bool,
        typer.Option("--no-sync", help="Skip automatic clock sync with the DC"),
    ] = False,
    no_hosts_sync: Annotated[
        bool,
        typer.Option(
            "--no-hosts-sync",
            help="Do not update /etc/hosts (default: auto-add DC FQDN via sudo)",
        ),
    ] = False,
) -> None:
    """Black-box recon: discover domain and AD surface from DC IP only (no credentials)."""
    from admapper.core.output import print_error
    from admapper.cli.scan import scan_engagement

    session = Session.bootstrap()
    try:
        scan_engagement(
            session,
            ip_dc=ip_dc,
            workspace=workspace,
            domain=domain,
            sync_clock=not no_sync,
            sync_hosts=not no_hosts_sync,
        )
    except (ValueError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@app.command("sync-dc")
def sync_dc(
    ip_dc: Annotated[
        str,
        typer.Option(
            "--ip-dc",
            "-H",
            "--host",
            help="Domain controller IP",
        ),
    ],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: derived from IP)"),
    ] = None,
    no_hosts_sync: Annotated[
        bool,
        typer.Option(
            "--no-hosts-sync",
            help="Only sync clock — do not update /etc/hosts",
        ),
    ] = False,
) -> None:
    """Sync local clock (and /etc/hosts) to the DC — run once with sudo, outside the dashboard UI."""
    from admapper.cli.scan import sync_dc_engagement
    from admapper.core.output import print_error

    session = Session.bootstrap()
    try:
        sync_dc_engagement(
            session,
            ip_dc=ip_dc,
            workspace=workspace,
            sync_hosts=not no_hosts_sync,
        )
    except (ValueError, RuntimeError, PermissionError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@app.command()
def run(
    host: Annotated[str, typer.Option("--host", "-H", help="Target IP or CIDR")],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: derived from host)"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Override inferred domain (optional)"),
    ] = None,
    user: Annotated[str | None, typer.Option("--user", "-u", help="Domain username")] = None,
    password: Annotated[str | None, typer.Option("--password", "-p", help="Password")] = None,
    full: Annotated[
        bool,
        typer.Option("--full", help="Pipeline completo (enum, cves, mssql, …)"),
    ] = False,
    minimal: Annotated[
        bool,
        typer.Option("--minimal", help="Solo auth + show (sin analyst)"),
    ] = False,
    clock_skew: Annotated[
        str | None,
        typer.Option(
            "--clock-skew",
            help="Kerberos clock offset for libfaketime (e.g. '+7h'). Auto-detected if omitted.",
        ),
    ] = None,
    no_sync: Annotated[
        bool,
        typer.Option("--no-sync", help="Skip automatic clock sync with the DC"),
    ] = False,
    no_hosts_sync: Annotated[
        bool,
        typer.Option(
            "--no-hosts-sync",
            help="Do not update /etc/hosts (default: auto-add DC FQDN via sudo)",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("-v", "--verbose", help="Full phase output, guides, and scenario report"),
    ] = False,
    auto: Annotated[
        bool,
        typer.Option("--auto", help="Chain owned/pivot, postex scan, and wired escalate steps"),
    ] = False,
) -> None:
    """Auth + analyst por defecto. Sin creds equivale a ``scan``."""
    session = Session.bootstrap()
    run_engagement(
        session,
        host=host,
        workspace=workspace,
        domain=domain,
        username=user,
        password=password,
        full=full,
        minimal=minimal,
        clock_skew=clock_skew,
        sync_clock=not no_sync,
        sync_hosts=not no_hosts_sync,
        verbose=verbose,
        auto=auto,
    )


@app.command("r", hidden=True)
def run_alias(
    host: Annotated[str, typer.Option("--host", "-H", help="Target IP or CIDR")],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: derived from host)"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Override inferred domain (optional)"),
    ] = None,
    user: Annotated[str | None, typer.Option("--user", "-u", help="Domain username")] = None,
    password: Annotated[str | None, typer.Option("--password", "-p", help="Password")] = None,
    full: Annotated[
        bool,
        typer.Option("--full", help="Pipeline completo (enum, cves, mssql, …)"),
    ] = False,
    minimal: Annotated[
        bool,
        typer.Option("--minimal", help="Solo auth + show (sin analyst)"),
    ] = False,
    clock_skew: Annotated[
        str | None,
        typer.Option(
            "--clock-skew",
            help="Kerberos clock offset for libfaketime (e.g. '+7h'). Auto-detected if omitted.",
        ),
    ] = None,
    no_sync: Annotated[
        bool,
        typer.Option("--no-sync", help="Skip automatic clock sync with the DC"),
    ] = False,
    no_hosts_sync: Annotated[
        bool,
        typer.Option(
            "--no-hosts-sync",
            help="Do not update /etc/hosts (default: auto-add DC FQDN via sudo)",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("-v", "--verbose", help="Full phase output, guides, and scenario report"),
    ] = False,
    auto: Annotated[
        bool,
        typer.Option("--auto", help="Chain owned/pivot, postex scan, and wired escalate steps"),
    ] = False,
) -> None:
    """Alias for run."""
    run(
        host=host,
        workspace=workspace,
        domain=domain,
        user=user,
        password=password,
        full=full,
        minimal=minimal,
        clock_skew=clock_skew,
        no_sync=no_sync,
        no_hosts_sync=no_hosts_sync,
        verbose=verbose,
        auto=auto,
    )


@app.command()
def analyst(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    clock_skew: Annotated[
        str | None,
        typer.Option("--clock-skew", help="Kerberos offset (e.g. '+7h')"),
    ] = None,
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Include paths, adcs, and postex"),
    ] = False,
    no_sync: Annotated[bool, typer.Option("--no-sync", help="Skip clock sync")] = False,
    no_refresh: Annotated[
        bool,
        typer.Option("--no-refresh", help="Read-only (like status)"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("-v", "--verbose", help="Full phase output, guides, and scenario report"),
    ] = False,
    auto: Annotated[
        bool,
        typer.Option("--auto", help="Chain owned/pivot, postex scan, and wired escalate steps"),
    ] = False,
) -> None:
    """Engagement map: pivot, creds, next hop (compact by default)."""
    from admapper.cli.brief import run_brief
    from admapper.core.output import print_error
    from admapper.core.verbosity import set_verbose

    session = Session.bootstrap()
    set_verbose(verbose)
    if workspace:
        session.select_workspace(workspace, create=False)
    elif session.workspace is None:
        print_error("sin workspace — usa: admapper run -H <ip> -u <user> -p '<pass>'")
        raise typer.Exit(1)
    try:
        run_brief(
            session,
            clock_skew=clock_skew,
            sync_clock=not no_sync,
            refresh=not no_refresh,
            deep=deep,
            auto=auto,
        )
        session.persist_workspace()
    except (ValueError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc


@app.command()
def graph(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    refresh: Annotated[
        bool,
        typer.Option("--refresh", help="Re-run paths analysis before showing graph"),
    ] = False,
    web: Annotated[
        bool,
        typer.Option("--web/--ascii", help="Generate interactive HTML (default) or ASCII terminal"),
    ] = True,
    serve: Annotated[
        bool,
        typer.Option("--serve", help="Start local HTTP server for attack_graph.html"),
    ] = False,
) -> None:
    """Attack graph — interactive web (default) or ASCII terminal."""
    from admapper.core.output import print_error, print_info, print_success
    from admapper.core.session import Session
    from admapper.analysis.user_match import refresh_workspace_intel

    session = Session.bootstrap()
    if workspace:
        session.select_workspace(workspace, create=False)
    elif session.workspace is None:
        print_error("sin workspace — usa -w <workspace>")
        raise typer.Exit(1)
    ws_path = session.workspaces.path_for(session.workspace.name)
    from admapper.creds.kerberos_skew import ensure_workspace_skew

    ensure_workspace_skew(ws_path)
    refresh_workspace_intel(ws_path)
    if refresh:
        from admapper.cli.commands import dispatch

        try:
            dispatch(session, "paths")
        except (ValueError, RuntimeError) as exc:
            print_error(str(exc))
            raise typer.Exit(1) from exc
    if web:
        from admapper.graph.web import write_attack_graph_html

        out = write_attack_graph_html(
            ws_path,
            workspace=session.workspace.name,
            domain=session.workspace.domain,
            pivot_user=session.workspace.pivot_user,
            owned_users=list(session.workspace.owned_users or []),
        )
        url = out.resolve().as_uri()
        print_success(f"attack graph → {out}")
        print_info(f"abrir: {url}")
        if serve:
            import http.server
            import os
            import threading
            import webbrowser

            os.chdir(ws_path)
            port = 8765
            handler = http.server.SimpleHTTPRequestHandler
            httpd = http.server.HTTPServer(("127.0.0.1", port), handler)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            open_url = f"http://127.0.0.1:{port}/attack_graph.html"
            print_info(f"serving {open_url}")
            try:
                webbrowser.open(open_url)
            except Exception:
                pass
            print_info("Ctrl+C para detener")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                httpd.shutdown()
        return
    from admapper.graph.show import print_attack_graph

    print_attack_graph(
        ws_path,
        domain=session.workspace.domain,
        pivot_user=session.workspace.pivot_user,
        owned_users=list(session.workspace.owned_users or []),
    )


@app.command("g", hidden=True)
def graph_alias(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    refresh: Annotated[
        bool,
        typer.Option("--refresh", help="Re-run paths analysis before showing graph"),
    ] = False,
    web: Annotated[
        bool,
        typer.Option("--web/--ascii", help="Generate interactive HTML (default) or ASCII terminal"),
    ] = True,
    serve: Annotated[
        bool,
        typer.Option("--serve", help="Start local HTTP server for attack_graph.html"),
    ] = False,
) -> None:
    """Alias for graph."""
    graph(
        workspace=workspace,
        refresh=refresh,
        web=web,
        serve=serve,
    )


@app.command()
def web(
    host: Annotated[
        str | None,
        typer.Option(
            "-H",
            "--host",
            "--ip",
            help="Target IP (creates workspace target-<ip>)",
        ),
    ] = None,
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    port: Annotated[
        int,
        typer.Option("--port", help="Dashboard server port (default 8766)"),
    ] = 8766,
    open_browser: Annotated[
        bool,
        typer.Option("--open/--no-open", help="Open dashboard in browser"),
    ] = True,
) -> None:
    """Web dashboard — live attack graph, terminal, and findings."""
    from admapper.cli.commands import dispatch
    from admapper.core.discovery import default_workspace_name
    from admapper.core.output import print_error, print_info
    from admapper.core.session import Session
    from admapper.graph.dashboard_server import run_dashboard_server

    # Require explicit target — never silently reuse the last active workspace
    if not host and not workspace:
        print_error(
            "specify a target:\n"
            "  admapper web -H <DC_IP>          # opens/creates workspace for that IP\n"
            "  admapper web -w <workspace_name> # opens existing workspace"
        )
        raise typer.Exit(1)

    session = Session.bootstrap()
    if host:
        ws_name = workspace or default_workspace_name(host)
        session.select_workspace(ws_name, create=True)
        dispatch(session, f"set hosts {host.strip()}")
        session.persist_workspace()
        print_info(f"workspace {ws_name} · target {host.strip()}")
    elif workspace:
        session.select_workspace(workspace, create=False)

    ws = session.workspace
    ws_path = session.workspaces.path_for(ws.name)
    if host and ws.hosts and ws.hosts.strip() != host.strip():
        ws = session.select_workspace(default_workspace_name(host), create=True)
        dispatch(session, f"set hosts {host.strip()}")
        session.persist_workspace()
        ws_path = session.workspaces.path_for(ws.name)
    elif host and not ws.hosts:
        dispatch(session, f"set hosts {host.strip()}")
        session.persist_workspace()
        ws_path = session.workspaces.path_for(ws.name)
        ws = session.workspace

    # Try to resolve domain and sync hosts mapping
    from admapper.core.discovery import resolve_domain, ensure_domain
    from admapper.cli.scan import sync_hosts_from_session
    from admapper.recon.unauth import run_unauth_scan

    resolved_domain = ws.domain or resolve_domain(session)
    if not resolved_domain and host:
        from admapper.recon.ports import scan_host
        print_info(f"Probing target DC reachability: {host.strip()}...")
        open_ports = scan_host(host.strip(), ports=(88, 389, 445, 636), timeout=1.0)
        if not open_ports:
            print_error(
                f"Error: Host {host.strip()} is unreachable or AD ports (88, 389, 445, 636) are closed.\n"
                "Please verify your connection/VPN and try again."
            )
            raise typer.Exit(1)

        print_info("No domain cached. Running unauthenticated discovery...")
        try:
            run_unauth_scan(session)
            resolved_domain = ensure_domain(session, announce=True)
        except Exception as exc:
            print_error(f"Unauthenticated discovery failed: {exc}")

    if resolved_domain:
        ws.domain = resolved_domain
        session.persist_workspace()
        sync_hosts_from_session(session, enabled=True)

    run_dashboard_server(
        ws_path=ws_path,
        workspace=ws.name,
        domain=ws.domain,
        owned_users=[],
        pivot_user=None,
        host=ws.hosts,
        port=port,
        open_browser=open_browser,
    )



@app.command()
def dashboard(
    host: Annotated[
        str | None,
        typer.Option(
            "-H",
            "--host",
            "--ip",
            help="Target IP — blackbox start (creates workspace target-<ip>)",
        ),
    ] = None,
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
    port: Annotated[
        int,
        typer.Option("--port", help="Dashboard server port (default 8766)"),
    ] = 8766,
    open_browser: Annotated[
        bool,
        typer.Option("--open/--no-open", help="Open dashboard in browser"),
    ] = True,
) -> None:
    """AD Ops — blackbox AD engagement dashboard (IP -> scan -> topology -> escalate)."""
    from admapper.cli.commands import dispatch
    from admapper.core.discovery import default_workspace_name
    from admapper.core.output import print_error, print_info
    from admapper.core.session import Session
    from admapper.graph.dashboard_server import run_dashboard_server
    from admapper.graph.ops_ui import write_ops_html

    # Require explicit target — never silently reuse the last active workspace
    if not host and not workspace:
        print_error(
            "specify a target:\n"
            "  admapper dashboard -H <DC_IP>          # opens/creates workspace for that IP\n"
            "  admapper dashboard -w <workspace_name> # opens existing workspace"
        )
        raise typer.Exit(1)

    session = Session.bootstrap()
    if host:
        ws_name = workspace or default_workspace_name(host)
        session.select_workspace(ws_name, create=True)
        dispatch(session, f"set hosts {host.strip()}")
        session.persist_workspace()
        print_info(f"blackbox → workspace {ws_name} · target {host.strip()}")
    elif workspace:
        session.select_workspace(workspace, create=False)
    ws = session.workspace
    ws_path = session.workspaces.path_for(ws.name)
    if host and ws.hosts and ws.hosts.strip() != host.strip():
        ws = session.select_workspace(default_workspace_name(host), create=True)
        dispatch(session, f"set hosts {host.strip()}")
        session.persist_workspace()
        ws_path = session.workspaces.path_for(ws.name)
    elif host and not ws.hosts:
        dispatch(session, f"set hosts {host.strip()}")
        session.persist_workspace()
        ws_path = session.workspaces.path_for(ws.name)
        ws = session.workspace

    # Try to resolve domain and sync hosts mapping
    from admapper.core.discovery import resolve_domain, ensure_domain
    from admapper.cli.scan import sync_hosts_from_session
    from admapper.recon.unauth import run_unauth_scan

    resolved_domain = ws.domain or resolve_domain(session)
    if not resolved_domain and host:
        from admapper.recon.ports import scan_host
        print_info(f"Probing target DC reachability: {host.strip()}...")
        open_ports = scan_host(host.strip(), ports=(88, 389, 445, 636), timeout=1.0)
        if not open_ports:
            print_error(
                f"Error: Host {host.strip()} is unreachable or AD ports (88, 389, 445, 636) are closed.\n"
                "Please verify your connection/VPN and try again."
            )
            raise typer.Exit(1)

        print_info("No domain cached. Running unauthenticated discovery...")
        try:
            run_unauth_scan(session)
            resolved_domain = ensure_domain(session, announce=True)
        except Exception as exc:
            print_error(f"Unauthenticated discovery failed: {exc}")

    if resolved_domain:
        ws.domain = resolved_domain
        session.persist_workspace()
        sync_hosts_from_session(session, enabled=True)

    write_ops_html(
        ws_path,
        workspace=ws.name,
        domain=ws.domain,
        pivot_user=ws.pivot_user,
        owned_users=list(ws.owned_users or []),
    )
    run_dashboard_server(
        ws_path=ws_path,
        workspace=ws.name,
        domain=ws.domain,
        owned_users=[],
        pivot_user=None,
        host=ws.hosts,
        port=port,
        open_browser=open_browser,
    )


@app.command(hidden=True)
def brief(
    workspace: Annotated[str | None, typer.Option("--workspace", "-w")] = None,
    clock_skew: Annotated[str | None, typer.Option("--clock-skew")] = None,
    no_sync: Annotated[bool, typer.Option("--no-sync")] = False,
    no_refresh: Annotated[bool, typer.Option("--no-refresh")] = False,
    auto: Annotated[
        bool,
        typer.Option("--auto", help="Chain owned/pivot, postex scan, and wired escalate steps"),
    ] = False,
) -> None:
    """Alias oculto de analyst."""
    analyst(
        workspace=workspace,
        clock_skew=clock_skew,
        deep=False,
        no_sync=no_sync,
        no_refresh=no_refresh,
        verbose=False,
        auto=auto,
    )


@app.command()
def winrm(
    host: Annotated[str, typer.Option("--host", "-H", help="DC IP or FQDN (e.g. dc01.corp.local)")],
    domain: Annotated[str, typer.Option("--domain", "-d", help="AD domain (e.g. corp.local)")],
    user: Annotated[str, typer.Option("--user", "-u", help="Username")],
    password: Annotated[
        str | None,
        typer.Option("--password", "-p", help="Password (for ticket acquisition)"),
    ] = None,
    hash: Annotated[
        str | None,
        typer.Option("--hash", help="NTLM hash for Pass-the-Hash (gMSA machine accounts)"),
    ] = None,
    dc_ip: Annotated[
        str | None,
        typer.Option("--dc-ip", help="DC IP for KDC (required when -H is an FQDN)"),
    ] = None,
    command: Annotated[
        str | None,
        typer.Option("--exec", "-x", help="Run one command and exit (default: interactive shell)"),
    ] = None,
    ccache: Annotated[
        str | None,
        typer.Option("--ccache", help="Existing MIT/impacket ccache (skip kinit/getTGT)"),
    ] = None,
    clock_skew: Annotated[
        str | None,
        typer.Option("--clock-skew", help="libfaketime offset for getTGT (e.g. '+7h')"),
    ] = None,
    no_sync: Annotated[bool, typer.Option("--no-sync", help="Skip automatic clock sync with the DC")] = False,
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Show kvno/klist and auth attempts")] = False,
    auto: Annotated[bool, typer.Option("--auto", help="Automatically mark compromised user as owned in the active workspace and run graph analysis")] = False,
) -> None:
    """WinRM shell — Kerberos via pypsrp, or Pass-the-Hash via nxc (--hash, no --dc-ip)."""
    from pathlib import Path

    from admapper.core.output import print_error
    from admapper.creds.common import resolve_dc_fqdn
    from admapper.winrm.shell_cli import run_winrm_shell

    if not password and not ccache and not hash:
        print_error("Provide --password, --hash, or --ccache")
        raise typer.Exit(1)

    if hash:
        # Pass-the-Hash: nxc connects to -H directly; no KDC / --dc-ip required.
        ip = dc_ip
        fqdn = host if host and not host[0].isdigit() else (
            resolve_dc_fqdn(None, domain, fallback_ip=ip) or host
        )
    else:
        ip = dc_ip
        if not ip and host and host[0].isdigit():
            ip = host
        if not ip:
            print_error("Provide --dc-ip <DC_IP> (required for Kerberos WinRM)")
            raise typer.Exit(1)
        fqdn = host if host and not host[0].isdigit() else None
        if not fqdn:
            fqdn = resolve_dc_fqdn(None, domain, fallback_ip=ip) or f"DC01.{domain.lower()}"

    run_winrm_shell(
        host=host,
        domain=domain,
        username=user,
        password=password,
        nthash=hash,
        dc_ip=ip,
        dc_fqdn=fqdn,
        command=command,
        ccache=Path(ccache) if ccache else None,
        clock_skew=clock_skew,
        sync_clock=not no_sync,
        verbose=verbose,
        auto=auto,
    )


@app.command()
def version() -> None:
    """Print ADMapper version."""
    typer.echo(__version__)


@app.command()
def doctor() -> None:
    """Validate repo layout, dependencies, and optional tools."""
    from admapper.core.install_check import print_doctor_report

    raise typer.Exit(code=print_doctor_report())


@app.command()
def status(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
) -> None:
    """Quick dashboard (no re-scan)."""
    from admapper.core.output import print_error
    from admapper.report.session_status import print_session_status

    session = Session.bootstrap()
    if workspace:
        session.select_workspace(workspace, create=False)
    elif session.workspace is None:
        print_error("no workspace — use: admapper status -w <name>")
        raise typer.Exit(1)
    print_session_status(session)


@app.command()
def exploit(
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace name (default: active workspace)"),
    ] = None,
    rounds: Annotated[
        int,
        typer.Option("--rounds", help="Max exploit chain rounds (1–10)"),
    ] = 3,
    clock_skew: Annotated[
        str | None,
        typer.Option(
            "--clock-skew",
            help="Kerberos clock offset when host and DC clocks differ (e.g. '+7h'). Uses libfaketime.",
        ),
    ] = None,
    no_sync: Annotated[
        bool,
        typer.Option("--no-sync", help="Skip automatic clock sync with the DC"),
    ] = False,
) -> None:
    """Auto-exploit chain: share loot → creds → ACL abuse → lateral."""
    from admapper.core.output import print_error
    from admapper.creds.kerberos_skew import apply_clock_skew_option
    from admapper.exploit.engine import run_exploit_engagement

    session = Session.bootstrap()
    if workspace:
        session.select_workspace(workspace, create=False)
    elif session.workspace is None:
        print_error("no active workspace — use: admapper run -H <ip> ... or exploit -w <name>")
        raise typer.Exit(code=1)

    apply_clock_skew_option(clock_skew)
    if session.workspace is not None:
        from admapper.creds.kerberos_skew import ensure_workspace_skew, save_workspace_clock_skew

        ws_path = session.workspaces.path_for(session.workspace.name)
        if clock_skew:
            save_workspace_clock_skew(ws_path, clock_skew)
        else:
            ensure_workspace_skew(ws_path)

    max_rounds = max(1, min(10, rounds))
    try:
        run_exploit_engagement(session, max_rounds=max_rounds, sync_clock=not no_sync)
        session.persist_workspace()
    except (ValueError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


opsec_app = typer.Typer(help="OPSEC profile management (Stealth / Normal / Lab)")
app.add_typer(opsec_app, name="opsec")


@opsec_app.callback(invoke_without_command=True)
def opsec_main(
    ctx: typer.Context,
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace"),
    ] = None,
) -> None:
    """Show current OPSEC profile and settings."""
    if ctx.invoked_subcommand is not None:
        return
    from admapper.core.opsec import print_opsec_status

    session = Session.bootstrap()
    if workspace:
        session.select_workspace(workspace, create=False)
    print_opsec_status(session if session.workspace else None)


@opsec_app.command("set")
def opsec_set(
    profile: Annotated[
        str,
        typer.Argument(help="Profile: stealth | normal | lab"),
    ],
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Workspace to apply profile to"),
    ] = None,
) -> None:
    """Set OPSEC profile for the active workspace.

    \b
    stealth  Minimum footprint: delays 3-10s, no spray, no coerce, confirms required
    normal   Balanced defaults (current ADMapper behaviour)
    lab      Maximum aggression: no delays, no confirmations (lab/testing use)
    """
    from admapper.core.output import print_error, print_success as _ps
    from admapper.core.opsec import OpsecProfile, save_workspace_profile, print_opsec_status

    try:
        p = OpsecProfile(profile.lower())
    except ValueError:
        print_error(f"unknown profile '{profile}' — choose: stealth, normal, lab")
        raise typer.Exit(code=1)

    session = Session.bootstrap()
    if workspace:
        session.select_workspace(workspace, create=False)
    elif session.workspace is None:
        print_error("no active workspace — use -w <name>")
        raise typer.Exit(code=1)

    ws_path = session.workspaces.path_for(session.workspace.name)
    save_workspace_profile(ws_path, p)
    _ps(f"OPSEC profile set to '{p.upper()}' for workspace '{session.workspace.name}'")
    print_opsec_status(session)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
