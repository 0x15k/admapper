from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from admapper.cli.commands._helpers import require_workspace
from admapper.core.output import print_error

if TYPE_CHECKING:
    from admapper.core.session import Session


def handle(session: Session, cmd: str, args: list[str]) -> bool | None:
    if cmd == "postex":
        if not require_workspace(session):
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

    if cmd == "wsus":
        if not require_workspace(session):
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

    return None
