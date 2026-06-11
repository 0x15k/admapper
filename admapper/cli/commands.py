from __future__ import annotations

import shlex
from pathlib import Path
from typing import TYPE_CHECKING

from admapper import __version__
from admapper.core.output import print_error, print_info, print_success, print_table, print_warning
from admapper.models.credential import CredentialType
from admapper.models.workspace import OperationMode

if TYPE_CHECKING:
    from admapper.core.session import Session

_HELP_ESSENTIAL = """
Essential (90% del engagement):
  show                         Dashboard: fase, creds, siguiente acción
  analyst [--deep]             Escenario completo + top 3 acciones
  start_unauth                 Recon sin creds
  start_auth                   Enum LDAP/SMB + BloodHound
  exploit                      Loot shares → creds → ACLs
  escalate                     Siguiente hop desde pivot
  escalate exec                Ejecutar hop recomendado
  creds list|add|verify        Gestión de credenciales
  acls | acls show <id>        ACL abuse
  adcs | postex | wsus         Módulos avanzados (show <id> en cada uno)
  export                       Reportes JSON/TXT/HTML
  guide <technique>            Pasos manuales MITRE
  help all                     Lista completa de comandos
  exit | quit
"""

_HELP_ALL = """
All commands:
  set workspace|domain|hosts|mode <value>
  workspaces                   List workspaces
  creds remove <id>
  enum users | enum auth
  asreproast | kerberoast | spray <pass>
  graph | graph show        Attack graph (ASCII, sin BloodHound CE)
  paths | paths show <id>
  kerberos | timeroast | coerce | chain | mssql | cves
  postex scan|deploy|run|show
  wsus run|script | adcs run
  escalate pivot|mark|refresh|sanitize
  cves exploit zerologon|nopac
  doctor | platform | version | scan
"""


def _require_workspace(session: Session) -> bool:
    if session.workspace is None:
        print_error("no active workspace — run: set workspace <name>")
        return False
    return True


def _parse_set_mode(value: str) -> OperationMode | None:
    try:
        return OperationMode(value.strip().lower())
    except ValueError:
        print_error("mode must be one of: auto, semi, manual")
        return None


def _parse_cred_type(value: str | None) -> CredentialType:
    if not value:
        return CredentialType.PASSWORD
    try:
        return CredentialType(value.strip().lower())
    except ValueError:
        print_warning(f"unknown cred type '{value}', using password")
        return CredentialType.PASSWORD


def dispatch(session: Session, line: str) -> bool:
    """Execute one shell line. Returns False when the shell should exit."""
    stripped = line.strip()
    if not stripped:
        return True

    try:
        parts = shlex.split(stripped)
    except ValueError as exc:
        print_error(f"invalid command quoting: {exc}")
        return True

    cmd = parts[0].lower()
    args = parts[1:]

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
        rows = [["name", "active"]] + [
            [name, "yes" if name == active else ""] for name in names
        ]
        print_table("Workspaces", rows[0], rows[1:])
        return True

    if cmd == "show":
        if not _require_workspace(session):
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
        if not _require_workspace(session):
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
            mode = _parse_set_mode(value)
            if mode is None:
                return True
            session.set_mode(mode)
            print_success(f"mode set: {mode.value}")
            return True
        print_error(f"unknown set target: {key}")
        return True

    if cmd == "creds":
        if len(args) < 1:
            print_error("usage: creds list|add|remove|verify ...")
            return True
        if not _require_workspace(session):
            return True
        store = session.credentials
        assert store is not None
        sub = args[0].lower()
        if sub == "list":
            creds = store.list()
            if not creds:
                print_warning("no credentials stored")
                return True
            rows = [
                [
                    c.id,
                    c.display_user(),
                    c.cred_type.value,
                    c.status.value,
                    c.source,
                ]
                for c in creds
            ]
            print_table("Credentials", ["id", "principal", "type", "status", "source"], rows)
            return True
        if sub == "add":
            if len(args) < 3:
                print_error("usage: creds add <user> <secret> [--domain D] [--type password|ntlm]")
                return True
            username = args[1]
            secret = args[2]
            domain: str | None = session.workspace.domain if session.workspace else None
            if not domain:
                from admapper.core.discovery import resolve_domain

                domain = resolve_domain(session)
                if domain and session.workspace:
                    session.set_domain(domain)
            cred_type = CredentialType.PASSWORD
            idx = 3
            while idx < len(args):
                flag = args[idx]
                if flag == "--domain" and idx + 1 < len(args):
                    domain = args[idx + 1]
                    idx += 2
                    continue
                if flag == "--type" and idx + 1 < len(args):
                    cred_type = _parse_cred_type(args[idx + 1])
                    idx += 2
                    continue
                print_error(f"unknown creds add flag: {flag}")
                return True
            cred = store.add(username, secret, domain=domain, cred_type=cred_type)
            print_success(f"credential added: {cred.display_user()} ({cred.id})")
            return True
        if sub == "remove":
            if len(args) < 2:
                print_error("usage: creds remove <id>")
                return True
            if store.remove(args[1]):
                print_success(f"credential removed: {args[1]}")
            else:
                print_error(f"credential not found: {args[1]}")
            return True
        if sub == "verify":
            if len(args) < 2:
                print_error("usage: creds verify <id>")
                return True
            from admapper.creds.verify import run_credential_verify

            try:
                run_credential_verify(session, args[1])
            except ValueError as exc:
                print_error(str(exc))
            except RuntimeError as exc:
                print_error(str(exc))
            return True
        print_error(f"unknown creds subcommand: {sub}")
        return True

    if cmd == "start_auth":
        if not _require_workspace(session):
            return True
        from admapper.auth.start_auth import run_start_auth

        cred_id: str | None = None
        idx = 0
        while idx < len(args):
            flag = args[idx]
            if flag == "--cred-id" and idx + 1 < len(args):
                cred_id = args[idx + 1]
                idx += 2
                continue
            print_error(f"unknown start_auth flag: {flag}")
            return True
        try:
            run_start_auth(session, cred_id=cred_id)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "start_unauth":
        if not _require_workspace(session):
            return True
        from admapper.recon.unauth import run_unauth_scan

        try:
            run_unauth_scan(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "enum":
        if len(args) < 1:
            print_error("usage: enum users|auth")
            return True
        if not _require_workspace(session):
            return True
        sub = args[0].lower()
        if sub == "auth":
            from admapper.auth.start_auth import run_start_auth

            cred_id: str | None = None
            idx = 1
            while idx < len(args):
                flag = args[idx]
                if flag == "--cred-id" and idx + 1 < len(args):
                    cred_id = args[idx + 1]
                    idx += 2
                    continue
                print_error(f"unknown enum auth flag: {flag}")
                return True
            try:
                run_start_auth(session, cred_id=cred_id)
            except ValueError as exc:
                print_error(str(exc))
            except RuntimeError as exc:
                print_error(str(exc))
            return True
        if sub != "users":
            print_error("usage: enum users|auth")
            return True
        from admapper.enum_pkg.scan import run_user_enumeration

        try:
            run_user_enumeration(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "asreproast":
        if not _require_workspace(session):
            return True
        from pathlib import Path

        from admapper.creds.asreproast import run_asreproast

        crack = True
        wordlist: Path | None = None
        users: list[str] = []
        idx = 0
        while idx < len(args):
            flag = args[idx]
            if flag == "--no-crack":
                crack = False
                idx += 1
                continue
            if flag == "--wordlist" and idx + 1 < len(args):
                wordlist = Path(args[idx + 1])
                idx += 2
                continue
            users.append(flag)
            idx += 1
        try:
            run_asreproast(
                session,
                usernames=users or None,
                wordlist=wordlist,
                crack=crack,
            )
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "kerberoast":
        if not _require_workspace(session):
            return True
        from pathlib import Path

        from admapper.creds.kerberoast import run_kerberoast

        crack = True
        wordlist: Path | None = None
        users: list[str] = []
        idx = 0
        while idx < len(args):
            flag = args[idx]
            if flag == "--no-crack":
                crack = False
                idx += 1
                continue
            if flag == "--wordlist" and idx + 1 < len(args):
                wordlist = Path(args[idx + 1])
                idx += 2
                continue
            users.append(flag)
            idx += 1
        try:
            run_kerberoast(
                session,
                usernames=users or None,
                wordlist=wordlist,
                crack=crack,
            )
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "spray":
        if not _require_workspace(session):
            return True
        from admapper.creds.spray import run_spray, run_spray_variations

        if not args:
            print_error("usage: spray <password> [user ...] | spray variations")
            return True

        method = "auto"
        dry_run = False
        force = False
        users: list[str] = []
        password: str | None = None
        variations_mode = args[0].lower() == "variations"

        if variations_mode:
            idx = 1
            while idx < len(args):
                flag = args[idx]
                if flag == "--dry-run":
                    dry_run = True
                    idx += 1
                    continue
                if flag == "--force":
                    force = True
                    idx += 1
                    continue
                if flag == "--method" and idx + 1 < len(args):
                    method = args[idx + 1]
                    idx += 2
                    continue
                users.append(flag)
                idx += 1
            try:
                run_spray_variations(
                    session,
                    usernames=users or None,
                    method=method,
                    dry_run=dry_run,
                    force=force,
                )
            except ValueError as exc:
                print_error(str(exc))
            except RuntimeError as exc:
                print_error(str(exc))
            return True

        idx = 0
        while idx < len(args):
            flag = args[idx]
            if flag == "--dry-run":
                dry_run = True
                idx += 1
                continue
            if flag == "--force":
                force = True
                idx += 1
                continue
            if flag == "--method" and idx + 1 < len(args):
                method = args[idx + 1]
                idx += 2
                continue
            if password is None:
                password = flag
            else:
                users.append(flag)
            idx += 1

        if password is None:
            print_error("usage: spray <password> [user ...]")
            return True

        try:
            run_spray(
                session,
                password,
                usernames=users or None,
                method=method,
                dry_run=dry_run,
                force=force,
            )
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
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
        from admapper.core.install_check import print_doctor_report

        print_doctor_report()
        return True

    if cmd == "platform":
        from admapper.core.tools_report import print_platform_report

        print_platform_report()
        return True

    if cmd == "graph":
        if not _require_workspace(session):
            return True
        ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
        from admapper.creds.kerberos_skew import ensure_workspace_skew
        from admapper.intel.user_match import refresh_workspace_intel

        ensure_workspace_skew(ws_path)
        refresh_workspace_intel(ws_path)
        if args and args[0].lower() == "show":
            from admapper.graph.web import write_attack_graph_html

            out = write_attack_graph_html(
                ws_path,
                workspace=session.workspace.name,  # type: ignore[union-attr]
                domain=session.workspace.domain,  # type: ignore[union-attr]
                pivot_user=session.workspace.pivot_user,  # type: ignore[union-attr]
                owned_users=list(session.workspace.owned_users or []),  # type: ignore[union-attr]
            )
            print_success(f"attack graph → {out}")
            print_info(f"abrir: {out.resolve().as_uri()}")
            return True
        from admapper.graph.analyze import run_graph_analysis
        from admapper.graph.web import write_attack_graph_html

        try:
            run_graph_analysis(session)
        except (ValueError, RuntimeError) as exc:
            print_error(str(exc))
            return True
        out = write_attack_graph_html(
            ws_path,
            workspace=session.workspace.name,  # type: ignore[union-attr]
            domain=session.workspace.domain,  # type: ignore[union-attr]
            pivot_user=session.workspace.pivot_user,  # type: ignore[union-attr]
            owned_users=list(session.workspace.owned_users or []),  # type: ignore[union-attr]
        )
        print_success(f"attack graph → {out}")
        print_info(f"abrir: {out.resolve().as_uri()}")
        return True

    if cmd == "paths":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: paths show <id>")
                return True
            from admapper.graph.analyze import get_path_detail
            from admapper.graph.render import print_path_detail

            detail = get_path_detail(session, args[1])
            if detail is None:
                print_error(f"path not found: {args[1]} — run paths first")
                return True
            print_path_detail(detail)
            return True

        from admapper.graph.analyze import run_graph_analysis

        try:
            run_graph_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "acls":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: acls show <id>")
                return True
            from admapper.acl.analyze import get_acl_finding
            from admapper.acl.render import print_acl_detail

            detail = get_acl_finding(session, args[1])
            if detail is None:
                print_error(f"ACL finding not found: {args[1]} — run acls first")
                return True
            print_acl_detail(detail)
            return True

        from admapper.acl.analyze import run_acl_analysis

        cred_id = None
        if "--cred-id" in args:
            idx = args.index("--cred-id")
            if idx + 1 < len(args):
                cred_id = args[idx + 1]

        try:
            run_acl_analysis(session, cred_id=cred_id)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "kerberos":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: kerberos show <id>")
                return True
            from admapper.kerberos.analyze import get_kerberos_op
            from admapper.kerberos.render import print_kerberos_op_detail

            detail = get_kerberos_op(session, args[1])
            if detail is None:
                print_error(f"Kerberos opportunity not found: {args[1]} — run kerberos first")
                return True
            print_kerberos_op_detail(detail)
            return True

        from admapper.kerberos.analyze import run_kerberos_analysis

        try:
            run_kerberos_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "timeroast":
        if not _require_workspace(session):
            return True
        from admapper.kerberos.timeroast import run_timeroast

        try:
            run_timeroast(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "adcs":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: adcs show <id>")
                return True
            from admapper.adcs.analyze import get_adcs_finding
            from admapper.adcs.render import print_adcs_detail

            detail = get_adcs_finding(session, args[1])
            if detail is None:
                print_error(f"AD CS finding not found: {args[1]} — run adcs first")
                return True
            print_adcs_detail(detail)
            return True

        if args and args[0].lower() == "run":
            finding_id = "adcs-002"
            dns_name = None
            cred_id = None
            i = 1
            while i < len(args):
                if args[i] in ("--finding", "-f") and i + 1 < len(args):
                    finding_id = args[i + 1]
                    i += 2
                elif args[i] == "--dns" and i + 1 < len(args):
                    dns_name = args[i + 1]
                    i += 2
                elif args[i] == "--cred-id" and i + 1 < len(args):
                    cred_id = args[i + 1]
                    i += 2
                elif args[i] == "enroll-hijack":
                    from admapper.adcs.runner import run_enroll_hijack

                    try:
                        run_enroll_hijack(
                            session,
                            finding_id=finding_id,
                            dns_name=dns_name or "DC01.logging.htb",
                            op_id="postex-010",
                        )
                    except (ValueError, RuntimeError) as exc:
                        print_error(str(exc))
                    return True
                else:
                    i += 1
            from admapper.adcs.runner import run_certipy_enrollment

            try:
                run_certipy_enrollment(
                    session,
                    finding_id=finding_id,
                    dns_name=dns_name,
                    cred_id=cred_id,
                )
            except (ValueError, RuntimeError) as exc:
                print_error(str(exc))
            return True

        from admapper.adcs.analyze import run_adcs_analysis

        cred_id = None
        if "--cred-id" in args:
            idx = args.index("--cred-id")
            if idx + 1 < len(args):
                cred_id = args[idx + 1]

        try:
            run_adcs_analysis(session, cred_id=cred_id)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "coerce":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: coerce show <id>")
                return True
            from admapper.coerce.analyze import get_coerce_op
            from admapper.coerce.render import print_coerce_detail

            detail = get_coerce_op(session, args[1])
            if detail is None:
                print_error(f"coerce opportunity not found: {args[1]} — run coerce first")
                return True
            print_coerce_detail(detail)
            return True

        from admapper.coerce.analyze import run_coerce_analysis

        try:
            run_coerce_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "postex":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: postex show <id>")
                return True
            from admapper.postex.analyze import get_postex_op
            from admapper.postex.render import print_postex_detail

            detail = get_postex_op(session, args[1])
            if detail is None:
                print_error(f"post-ex opportunity not found: {args[1]} — run postex first")
                return True
            print_postex_detail(detail)
            return True

        if args and args[0].lower() == "deploy":
            from admapper.postex.deploy import deploy_dll_hijack

            op_id = None
            lhost = None
            lport = 4444
            dry_run = False
            payload = None
            i = 1
            while i < len(args):
                if args[i] in ("--op", "-o") and i + 1 < len(args):
                    op_id = args[i + 1]
                    i += 2
                elif args[i] == "--lhost" and i + 1 < len(args):
                    lhost = args[i + 1]
                    i += 2
                elif args[i] == "--lport" and i + 1 < len(args):
                    lport = int(args[i + 1])
                    i += 2
                elif args[i] == "--payload" and i + 1 < len(args):
                    payload = Path(args[i + 1])
                    i += 2
                elif args[i] == "--dry-run":
                    dry_run = True
                    i += 1
                else:
                    i += 1
            try:
                deploy_dll_hijack(
                    session,
                    op_id=op_id,
                    lhost=lhost,
                    lport=lport,
                    payload_dll=payload,
                    dry_run=dry_run,
                )
            except (ValueError, RuntimeError, FileNotFoundError) as exc:
                print_error(str(exc))
            return True

        if args and args[0].lower() == "run":
            from admapper.postex.runner import run_dll_hijack

            op_id = None
            lhost = None
            lport = 4444
            wait = 180
            payload = None
            i = 1
            while i < len(args):
                if args[i] in ("--op", "-o") and i + 1 < len(args):
                    op_id = args[i + 1]
                    i += 2
                elif args[i] == "--lhost" and i + 1 < len(args):
                    lhost = args[i + 1]
                    i += 2
                elif args[i] == "--lport" and i + 1 < len(args):
                    lport = int(args[i + 1])
                    i += 2
                elif args[i] == "--wait" and i + 1 < len(args):
                    wait = int(args[i + 1])
                    i += 2
                elif args[i] == "--payload" and i + 1 < len(args):
                    payload = Path(args[i + 1])
                    i += 2
                else:
                    i += 1
            try:
                run_dll_hijack(
                    session,
                    op_id=op_id,
                    lhost=lhost,
                    lport=lport,
                    payload_dll=payload,
                    wait_seconds=wait,
                )
            except (ValueError, RuntimeError, FileNotFoundError) as exc:
                print_error(str(exc))
            return True

        if args and args[0].lower() == "scan":
            from admapper.postex.analyze import run_postex_analysis

            try:
                run_postex_analysis(session, remote_scan=True)
            except ValueError as exc:
                print_error(str(exc))
            except RuntimeError as exc:
                print_error(str(exc))
            return True

        from admapper.postex.analyze import run_postex_analysis

        try:
            run_postex_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "mssql":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: mssql show <id>")
                return True
            from admapper.mssql.analyze import get_mssql_finding
            from admapper.mssql.render import print_mssql_detail

            detail = get_mssql_finding(session, args[1])
            if detail is None:
                print_error(f"MSSQL finding not found: {args[1]} — run mssql first")
                return True
            print_mssql_detail(detail)
            return True

        from admapper.mssql.analyze import run_mssql_analysis

        try:
            run_mssql_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "wsus":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: wsus show <id>")
                return True
            from admapper.wsus.analyze import get_wsus_op
            from admapper.wsus.render import print_wsus_detail

            detail = get_wsus_op(session, args[1])
            if detail is None:
                print_error(f"WSUS opportunity not found: {args[1]} — run wsus first")
                return True
            print_wsus_detail(detail)
            return True

        if args and args[0].lower() == "script":
            from admapper.wsus.runner import write_wsus_publish_script

            try:
                write_wsus_publish_script(session)
            except (ValueError, RuntimeError) as exc:
                print_error(str(exc))
            return True

        if args and args[0].lower() == "run":
            from admapper.wsus.runner import run_wsus_cert_chain

            op_id = "wsus-004"
            skip_enroll = False
            i = 1
            while i < len(args):
                if args[i] in ("--op", "-o") and i + 1 < len(args):
                    op_id = args[i + 1]
                    i += 2
                elif args[i] == "--no-enroll":
                    skip_enroll = True
                    i += 1
                else:
                    i += 1
            try:
                run_wsus_cert_chain(session, op_id=op_id, enroll=not skip_enroll)
            except (ValueError, RuntimeError) as exc:
                print_error(str(exc))
            return True

        from admapper.wsus.analyze import run_wsus_analysis

        try:
            run_wsus_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "chain":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: chain show <id>")
                return True
            from admapper.chain.analyze import get_chain_op
            from admapper.chain.render import print_chain_detail

            detail = get_chain_op(session, args[1])
            if detail is None:
                print_error(f"attack chain not found: {args[1]} — run chain first")
                return True
            print_chain_detail(detail)
            return True

        from admapper.chain.analyze import run_chain_analysis

        try:
            run_chain_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "escalate":
        if not _require_workspace(session):
            return True
        from admapper.escalate.analyze import (
            mark_user_owned,
            run_escalate_analysis,
            run_pivot_refresh,
            set_pivot_user,
        )

        sub = (args[0].lower() if args else "")
        try:
            if sub == "pivot":
                if len(args) < 2:
                    print_error("usage: escalate pivot <user>")
                    return True
                set_pivot_user(session, args[1])
                run_escalate_analysis(session, pivot_user=args[1])
            elif sub == "mark":
                if len(args) < 2:
                    print_error("usage: escalate mark <user>")
                    return True
                mark_user_owned(session, args[1], refresh=False)
            elif sub == "sanitize":
                from admapper.core.owned import sanitize_owned_users

                clean, removed = sanitize_owned_users(list(session.workspace.owned_users or []))
                session.workspace.owned_users = clean
                session.persist_workspace()
                if removed:
                    print_success(f"removed: {', '.join(removed)}")
                else:
                    print_info("owned_users already clean")
                run_escalate_analysis(session)
            elif sub == "refresh":
                from admapper.escalate.analyze import resolve_pivot_user

                run_pivot_refresh(session, resolve_pivot_user(session))
                run_escalate_analysis(session)
            elif sub == "exec":
                from admapper.escalate.analyze import run_escalate_exec

                op_id = None
                if len(args) > 1 and not args[1].startswith("-"):
                    op_id = args[1]
                run_escalate_exec(session, op_id=op_id)
            else:
                run_escalate_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "cves":
        if not _require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: cves show <id>")
                return True
            from admapper.cves.analyze import get_cve_finding
            from admapper.cves.render import print_cve_detail

            detail = get_cve_finding(session, args[1])
            if detail is None:
                print_error(f"CVE finding not found: {args[1]} — run cves first")
                return True
            print_cve_detail(detail)
            return True
        if args and args[0].lower() == "exploit":
            if len(args) < 2:
                print_error("usage: cves exploit zerologon <host> | cves exploit nopac")
                return True
            exploit_kind = args[1].lower()
            try:
                if exploit_kind == "zerologon":
                    if len(args) < 3:
                        print_error("usage: cves exploit zerologon <host>")
                        return True
                    from admapper.cves.exploit import run_zerologon_exploit

                    run_zerologon_exploit(session, args[2])
                elif exploit_kind == "nopac":
                    from admapper.cves.exploit import run_nopac_confirm

                    run_nopac_confirm(session)
                else:
                    print_error(f"unknown exploit: {exploit_kind}")
            except ValueError as exc:
                print_error(str(exc))
            except RuntimeError as exc:
                print_error(str(exc))
            return True

        from admapper.cves.analyze import run_cve_analysis

        try:
            run_cve_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd == "exploit":
        if not _require_workspace(session):
            return True
        from admapper.exploit.engine import run_exploit_engagement

        max_rounds = 3
        if args and args[0].lower() == "--rounds":
            if len(args) < 2:
                print_error("usage: exploit [--rounds N]")
                return True
            try:
                max_rounds = max(1, min(10, int(args[1])))
            except ValueError:
                print_error("--rounds requires an integer")
                return True
        try:
            run_exploit_engagement(session, max_rounds=max_rounds)
            session.persist_workspace()
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    if cmd in {"brief", "analyst"}:
        if not _require_workspace(session):
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
        if not _require_workspace(session):
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

    print_error(f"unknown command: {cmd} — type 'help'")
    return True
