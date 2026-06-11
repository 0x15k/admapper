from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from admapper.cli.commands._helpers import parse_cred_type, require_workspace
from admapper.core.output import print_error, print_success, print_table, print_warning
from admapper.models.credential import CredentialType

if TYPE_CHECKING:
    from admapper.core.session import Session


def handle(session: Session, cmd: str, args: list[str]) -> bool | None:
    if cmd == "creds":
        if len(args) < 1:
            print_error("usage: creds list|add|remove|verify ...")
            return True
        if not require_workspace(session):
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
                    cred_type = parse_cred_type(args[idx + 1])
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

    if cmd == "asreproast":
        if not require_workspace(session):
            return True
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
        if not require_workspace(session):
            return True
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
        if not require_workspace(session):
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

    return None
