from __future__ import annotations

from typing import TYPE_CHECKING

from admapper import __version__
from admapper.cli.commands._helpers import (
    _HELP_ALL,
    _HELP_ESSENTIAL,
    parse_set_mode,
    require_workspace,
)
from admapper.support.output import (
    print_error,
    print_info,
    print_success,
    print_table,
    print_warning,
)

if TYPE_CHECKING:
    from admapper.support.session import Session


def handle(session: Session, cmd: str, args: list[str]) -> bool | None:
    """Handle meta / shell commands. Return None if not handled."""
    if cmd in {"exit", "quit"}:
        if session.workspace is not None:
            session.persist_workspace()
        print_info("bye")
        return False

    if cmd == "help":
        if args and args[0].lower() == "all":
            print_info(_HELP_ESSENTIAL.strip())
            print_info(_HELP_ALL.strip())
        else:
            print_info(_HELP_ESSENTIAL.strip())
        return True

    if cmd == "version":
        print_info(f"ADMapper {__version__}")
        return True

    if cmd == "workspaces":
        print_info(f"workspaces root: {session.workspaces.root}")
        names = session.workspaces.list_workspaces()
        if not names:
            print_warning("no workspaces yet — run: set workspace <name>")
            return True
        active = session.workspace.name if session.workspace else None
        rows = [["name", "active"]] + [[name, "yes" if name == active else ""] for name in names]
        print_table("Workspaces", rows[0], rows[1:])
        return True

    if cmd == "show":
        if not require_workspace(session):
            return True
        from admapper.report.session_status import print_session_status

        print_session_status(session)
        return True

    if cmd == "set":
        if len(args) < 2:
            print_error("usage: set workspace|workspaces|domain|hosts|mode <value>")
            return True
        key, *values = args
        value = " ".join(values)
        if key == "workspace":
            session.select_workspace(value)
            print_success(f"workspace active: {session.workspace.name}")
            return True
        if key == "workspaces":
            root = session.set_workspaces_root(value)
            print_success(f"workspaces root: {root}")
            return True
        if not require_workspace(session):
            return True
        if key == "domain":
            session.set_domain(value)
            print_success(f"domain set: {session.workspace.domain}")
            return True
        if key == "hosts":
            session.set_hosts(value)
            print_success(f"hosts set: {session.workspace.hosts}")
            return True
        if key == "mode":
            mode = parse_set_mode(value)
            if mode is None:
                return True
            session.set_mode(mode)
            print_success(f"mode set: {mode.value}")
            return True
        print_error(f"unknown set target: {key}")
        return True

    if cmd == "scan":
        if not args:
            print_error("usage: scan <dc-ip>")
            return True
        from admapper.cli.scan import scan_engagement

        try:
            scan_engagement(session, ip_dc=args[0])
        except (ValueError, RuntimeError) as exc:
            print_error(str(exc))
        return True

    if cmd == "doctor":
        from admapper.support.install_check import print_doctor_report

        print_doctor_report()
        return True

    if cmd == "platform":
        from admapper.support.tools_report import print_platform_report

        print_platform_report()
        return True

    if cmd in {"brief", "analyst"}:
        if not require_workspace(session):
            return True
        from admapper.cli.brief import run_brief

        deep = "--deep" in args
        try:
            run_brief(session, refresh=True, deep=deep)
            session.persist_workspace()
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "export":
        if not require_workspace(session):
            return True
        from admapper.report.export import run_export

        kind = args[0].lower() if args else "all"
        try:
            if kind in ("all", ""):
                run_export(session)
            elif kind == "json":
                run_export(session, export_txt=False, export_navigator=False)
            elif kind == "txt":
                run_export(session, export_json=False, export_navigator=False)
            elif kind == "navigator":
                run_export(session, export_json=False, export_txt=False)
            else:
                print_error("usage: export [json|txt|navigator]")
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "guide":
        if len(args) < 1:
            print_error("usage: guide <technique>")
            print_info(
                "keys: dns_domain_controllers, ldap_anonymous, smb_null, "
                "samr_enumeration, ldap_user_enum, rid_cycling, asreproast, "
                "kerberoast, passwordspray, creds_verify, start_auth, auth_enum, "
                "attack_paths, acl_abuse, kerberos_adv, timeroasting, adcs_esc, "
                "golden_cert, coercion, ntlm_relay, postex_local, wsus_esc, attack_chain, "
                "escalate, mssql_lateral, "
                "cves_exploit"
            )
            return True
        from admapper.guides.render import print_manual_guide

        print_manual_guide(args[0].lower(), session=session)
        return True

    return None
