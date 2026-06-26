from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.cli.commands._helpers import require_workspace
from admapper.support.output import print_error

if TYPE_CHECKING:
    from admapper.support.session import Session


def handle(session: Session, cmd: str, args: list[str]) -> bool | None:
    if cmd == "start_auth":
        if not require_workspace(session):
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
        if not require_workspace(session):
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
        if not require_workspace(session):
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
        from admapper.enumeration.scan import run_user_enumeration

        try:
            run_user_enumeration(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    return None
