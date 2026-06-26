from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.cli.commands._helpers import require_workspace
from admapper.support.output import print_error, print_info, print_success

if TYPE_CHECKING:
    from admapper.support.session import Session


def handle(session: Session, cmd: str, args: list[str]) -> bool | None:
    if cmd == "escalate":
        if not require_workspace(session):
            return True
        from admapper.escalate.analyze import (
            mark_user_owned,
            run_escalate_analysis,
            run_pivot_refresh,
            set_pivot_user,
        )

        sub = args[0].lower() if args else ""
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
                from admapper.support.owned import sanitize_owned_users

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

    if cmd == "exploit":
        if not require_workspace(session):
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

    return None
