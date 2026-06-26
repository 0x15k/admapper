from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_guide
from admapper.models.credential import CredentialStatus
from admapper.models.mssql_op import MssqlOpportunity
from admapper.mssql.catalog import mssql_meta
from admapper.mssql.discover import discover_mssql_instances
from admapper.mssql.enum import MssqlEnumResult, enumerate_mssql_instance

if TYPE_CHECKING:
    from admapper.support.session import Session


def _pick_credential(session: Session, cred_id: str | None):
    from admapper.models.credential import Credential

    store = session.credentials
    if store is None:
        raise RuntimeError("credential store unavailable")
    creds = store.list()
    if not creds:
        raise ValueError("no credentials — run start_auth or creds add")

    if cred_id:
        cred = next((c for c in creds if c.id == cred_id), None)
        if cred is None:
            raise ValueError(f"credential not found: {cred_id}")
        return cred

    owned = {u.lower() for u in (session.workspace.owned_users if session.workspace else [])}
    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret and cred.username.lower() in owned:
                return cred
    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret:
                return cred
    raise ValueError("no usable credential for MSSQL enum")


def _opportunity(
    technique: str,
    *,
    target_host: str,
    context: str | None = None,
    detail: str = "",
) -> MssqlOpportunity:
    meta = mssql_meta(technique)
    return MssqlOpportunity(
        technique=technique,
        title=meta.title,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        summary=meta.summary,
        target_host=target_host,
        context=context,
        detail=detail,
        manual_commands=list(meta.manual_commands),
    )


def _opportunities_from_enum(
    enum_result: MssqlEnumResult,
    *,
    context: str,
) -> list[MssqlOpportunity]:
    ops: list[MssqlOpportunity] = []
    host = enum_result.host
    if not enum_result.login_ok:
        return ops

    ops.append(_opportunity("sql_access", target_host=host, context=context))

    if enum_result.is_sysadmin:
        ops.append(
            _opportunity(
                "sql_admin",
                target_host=host,
                context=context,
                detail="IS_SRVROLEMEMBER('sysadmin') = 1",
            )
        )
        ops.append(
            _opportunity(
                "xp_cmdshell",
                target_host=host,
                context=context,
                detail="sysadmin can enable/run xp_cmdshell",
            )
        )
    elif enum_result.xp_cmdshell_enabled:
        ops.append(
            _opportunity(
                "xp_cmdshell",
                target_host=host,
                context=context,
                detail="xp_cmdshell enabled in sys.configurations",
            )
        )

    ops.append(
        _opportunity(
            "impersonate",
            target_host=host,
            context=context,
            detail="Check IMPERSONATE privilege with nxc mssql --impersonate",
        )
    )

    for linked in enum_result.linked_servers:
        ops.append(
            _opportunity(
                "linked_server",
                target_host=host,
                context=context,
                detail=f"linked server: {linked}",
            )
        )

    for db in enum_result.trustworthy_databases:
        ops.append(
            _opportunity(
                "trustworthy",
                target_host=host,
                context=context,
                detail=f"TRUSTWORTHY ON database: {db}",
            )
        )

    return ops


def build_mssql_opportunities(
    instances: list,
    enum_results: list[MssqlEnumResult],
    *,
    context: str,
) -> list[MssqlOpportunity]:
    ops: list[MssqlOpportunity] = []
    enum_by_host = {r.host.lower(): r for r in enum_results}

    for instance in instances:
        host = instance.host
        enum_result = enum_by_host.get(host.lower())
        if enum_result and enum_result.login_ok:
            ops.extend(_opportunities_from_enum(enum_result, context=context))
        else:
            ops.append(
                _opportunity(
                    "sql_access",
                    target_host=host,
                    context=context,
                    detail="MSSQL port/SPN discovered — try owned creds",
                )
            )
            ops.append(
                _opportunity(
                    "impersonate",
                    target_host=host,
                    context=context,
                    detail="Enumerate IMPERSONATE after successful login",
                )
            )

    seen: set[tuple[str, str, str]] = set()
    unique: list[MssqlOpportunity] = []
    for op in ops:
        key = (op.technique, op.target_host.lower(), op.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(op)
    return unique


@dataclass
class MssqlAnalysisResult:
    opportunities: list[MssqlOpportunity] = field(default_factory=list)
    inventory_path: str | None = None
    findings_path: str | None = None
    errors: list[str] = field(default_factory=list)


def run_mssql_analysis(session: Session, *, cred_id: str | None = None) -> MssqlAnalysisResult:
    """Phase 15 — MSSQL discovery, enum, and lateral movement playbook."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before mssql")

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)

    print_info("Phase 15 — MSSQL analysis")

    instances = discover_mssql_instances(session)
    if not instances:
        print_warning("no MSSQL instances found — check hosts (1433) or kerberoast SPNs")
    else:
        print_success(f"discovered {len(instances)} MSSQL target(s)")

    cred = _pick_credential(session, cred_id)
    context = cred.display_user()

    enum_results: list[MssqlEnumResult] = []
    errors: list[str] = []
    for instance in instances[:10]:
        print_info(f"enumerating MSSQL @ {instance.host}:{instance.port}")
        result = enumerate_mssql_instance(instance, cred, domain)
        enum_results.append(result)
        if result.error and not result.login_ok:
            errors.append(f"{instance.host}: {result.error}")

    opportunities = build_mssql_opportunities(
        instances,
        enum_results,
        context=context,
    )
    for idx, op in enumerate(opportunities, start=1):
        op.id = f"mssql-{idx:03d}"

    analysis = MssqlAnalysisResult(
        opportunities=opportunities,
        errors=errors,
    )

    inv_path = ws_path / "mssql_inventory.json"
    inv_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "credential": context,
                "instances": [i.to_dict() for i in instances],
                "enum": [
                    {
                        "host": r.host,
                        "login_ok": r.login_ok,
                        "is_sysadmin": r.is_sysadmin,
                        "linked_servers": r.linked_servers,
                        "trustworthy_databases": r.trustworthy_databases,
                        "xp_cmdshell_enabled": r.xp_cmdshell_enabled,
                        "error": r.error,
                    }
                    for r in enum_results
                ],
                "errors": errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    analysis.inventory_path = str(inv_path)

    findings_path = ws_path / "mssql_findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "finding_count": len(opportunities),
                "findings": [o.to_dict() for o in opportunities],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    analysis.findings_path = str(findings_path)

    if opportunities:
        rows = [
            [o.id, o.technique, o.target_host, o.severity, o.detail[:40]]
            for o in opportunities[:20]
        ]
        print_table("MSSQL opportunities", ["id", "technique", "host", "severity", "detail"], rows)
    else:
        print_warning("no MSSQL opportunities — verify creds and port 1433 access")

    print_success("MSSQL inventory saved → mssql_inventory.json")
    print_success("MSSQL findings saved → mssql_findings.json")
    print_manual_guide("mssql_lateral", session=session)
    return analysis


def get_mssql_finding(session: Session, finding_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "mssql_findings.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("findings", []):
        if str(item.get("id")) == finding_id:
            return item
    return None
