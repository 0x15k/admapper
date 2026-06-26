from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.cli.commands._helpers import require_workspace
from admapper.support.output import print_error

if TYPE_CHECKING:
    from admapper.support.session import Session


def handle(session: Session, cmd: str, args: list[str]) -> bool | None:
    if cmd == "acls":
        if not require_workspace(session):
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
        if not require_workspace(session):
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
        if not require_workspace(session):
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
        if not require_workspace(session):
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
                    from admapper.creds.common import pick_dc_ip, resolve_dc_fqdn

                    resolved_dns = dns_name
                    if not resolved_dns:
                        domain = session.workspace.domain if session.workspace else None
                        ws_path = (
                            session.workspaces.path_for(session.workspace.name)
                            if session.workspace
                            else None
                        )
                        dc_ip = pick_dc_ip(session)
                        if domain and ws_path:
                            resolved_dns = (
                                resolve_dc_fqdn(str(ws_path), domain, fallback_ip=dc_ip)
                                or f"dc01.{domain}"
                            )
                    if not resolved_dns:
                        raise ValueError(
                            "dns_name could not be resolved from workspace — please specify it with --dns"
                        )

                    try:
                        run_enroll_hijack(
                            session,
                            finding_id=finding_id,
                            dns_name=resolved_dns,
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
        if not require_workspace(session):
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

    if cmd == "mssql":
        if not require_workspace(session):
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

    if cmd == "chain":
        if not require_workspace(session):
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

    if cmd == "cves":
        if not require_workspace(session):
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

    return None
