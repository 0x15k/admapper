from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from admapper.core.findings import FindingsStore
from admapper.core.hosts import HostsStore
from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.core.users import UsersStore
from admapper.enumeration.ldap_users import enumerate_users_ldap
from admapper.enumeration.rid_cycle import cycle_rids
from admapper.enumeration.samr import enumerate_users_samr
from admapper.guides.render import print_manual_guides_for_keys
from admapper.models.finding import Finding, FindingSeverity
from admapper.models.user import UserRecord

if TYPE_CHECKING:
    from admapper.core.session import Session

_SENSITIVE_DESC = re.compile(
    r"password|passwd|pwd|credential|secret|ntlm|passwort|contrase",
    re.IGNORECASE,
)


@dataclass
class UserEnumResult:
    users: list[UserRecord] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
    guides_shown: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _pick_dc_hosts(session: Session) -> list[str]:
    if session.workspace is None:
        return []
    hosts_store = HostsStore(session.workspaces, session.workspace.name)
    hosts = hosts_store.list()
    dcs = [h.address for h in hosts if h.is_domain_controller]
    if dcs:
        return dcs
    ldap_hosts = [h.address for h in hosts if 389 in h.open_ports]
    if ldap_hosts:
        return ldap_hosts[:3]
    smb_hosts = [h.address for h in hosts if 445 in h.open_ports]
    return smb_hosts[:3]


def _sensitive_descriptions(users: list[UserRecord]) -> list[UserRecord]:
    flagged: list[UserRecord] = []
    for user in users:
        if user.description and _SENSITIVE_DESC.search(user.description):
            flagged.append(user)
    return flagged


def run_user_enumeration(session: Session) -> UserEnumResult:
    """P03 Identity surface — enumerate AD users from SAMR, LDAP, and RID cycling."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    ws_name = session.workspace.name
    users_store = UsersStore(session.workspaces, ws_name)
    findings_store = FindingsStore(session.workspaces, ws_name)
    result = UserEnumResult()

    targets = _pick_dc_hosts(session)
    if not targets:
        raise ValueError("no DC candidates — run start_unauth first or set hosts")

    from admapper.core.phases import phase_banner
    from admapper.core.verbosity import print_phase

    print_phase(phase_banner("p03", detail=f"user enumeration on {', '.join(targets)}"))
    collected: list[UserRecord] = []
    guides_to_show: list[str] = []

    for host in targets:
        print_info(f"LDAP user enum: {host}")
        ldap_result = enumerate_users_ldap(host)
        if ldap_result.error:
            result.errors.append(f"ldap:{host}: {ldap_result.error}")
            print_warning(f"LDAP enum failed on {host}: {ldap_result.error}")
        elif ldap_result.users:
            result.sources_used.append("ldap")
            guides_to_show.append("ldap_user_enum")
            collected.extend(ldap_result.users)
            print_success(f"LDAP: {len(ldap_result.users)} user(s) from {host}")

        print_info(f"SAMR user enum: {host}")
        samr_result = enumerate_users_samr(host)
        if samr_result.error:
            result.errors.append(f"samr:{host}: {samr_result.error}")
            if "impacket" in (samr_result.error or "").lower():
                print_warning(samr_result.error)
            else:
                print_warning(f"SAMR failed on {host}: {samr_result.error}")
        elif samr_result.users:
            result.sources_used.append("samr")
            guides_to_show.append("samr_enumeration")
            collected.extend(samr_result.users)
            print_success(f"SAMR: {len(samr_result.users)} user(s) from {host}")

    merged = users_store.merge(collected)
    human_users = [u for u in merged if not u.is_machine_account]

    if len(human_users) < 5:
        host = targets[0]
        print_info(f"RID cycling fallback: {host} (few users from LDAP/SAMR)")
        rid_result = cycle_rids(host, start_rid=500, end_rid=2500)
        if rid_result.error:
            result.errors.append(f"rid:{host}: {rid_result.error}")
            print_warning(rid_result.error or "RID cycling failed")
        elif rid_result.users:
            result.sources_used.append("rid_cycling")
            guides_to_show.append("rid_cycling")
            merged = users_store.merge(rid_result.users)
            human_users = [u for u in merged if not u.is_machine_account]
            print_success(
                f"RID cycling: {len(rid_result.users)} user(s), "
                f"{rid_result.rids_scanned} RIDs scanned"
            )

    result.users = merged
    from admapper.intel.user_match import refresh_workspace_intel

    refresh_workspace_intel(session.workspaces.path_for(ws_name))
    asrep = [u for u in human_users if u.asrep_roastable]
    kerb = [u for u in human_users if u.kerberoastable]
    sensitive = _sensitive_descriptions(human_users)

    findings: list[Finding] = [
        Finding(
            key="user_inventory",
            title=f"Domain user inventory ({len(human_users)} human accounts)",
            severity=FindingSeverity.INFO,
            source="enum_users",
            detail=f"sources={sorted(set(result.sources_used))}",
            mitre_id="T1087.002",
        )
    ]
    if asrep:
        findings.append(
            Finding(
                key="asrep_roastable_users",
                title=f"AS-REP roastable accounts ({len(asrep)})",
                severity=FindingSeverity.MEDIUM,
                source="enum_users",
                detail=", ".join(u.username for u in asrep[:10]),
                mitre_id="T1558.004",
            )
        )
        guides_to_show.append("asreproast")
    if kerb:
        findings.append(
            Finding(
                key="kerberoastable_users",
                title=f"Kerberoastable accounts ({len(kerb)})",
                severity=FindingSeverity.MEDIUM,
                source="enum_users",
                detail=", ".join(u.username for u in kerb[:10]),
                mitre_id="T1558.003",
            )
        )
        guides_to_show.append("kerberoast")
    for user in sensitive:
        findings.append(
            Finding(
                key=f"sensitive_description_{user.username}",
                title="Sensitive keyword in user description",
                severity=FindingSeverity.HIGH,
                source="enum_users",
                detail=user.description or "",
                mitre_id="T1087.002",
            )
        )

    findings_store.merge(findings)

    rows = [
        [
            u.username,
            ",".join(u.sources),
            "yes" if u.asrep_roastable else "",
            "yes" if u.kerberoastable else "",
            (u.description or "")[:40],
        ]
        for u in human_users[:25]
    ]
    if rows:
        print_table(
            f"Users ({len(human_users)} human, showing up to 25)",
            ["user", "sources", "asrep", "kerb", "description"],
            rows,
        )
    print_success(f"users saved → users.json ({len(merged)} total accounts)")

    report_path = session.workspaces.path_for(ws_name) / "user_enum.json"
    report_path.write_text(
        json.dumps(
            {
                "sources_used": sorted(set(result.sources_used)),
                "human_count": len(human_users),
                "total_count": len(merged),
                "asrep_roastable": [u.username for u in asrep],
                "kerberoastable": [u.username for u in kerb],
                "errors": result.errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    result.guides_shown = sorted(set(guides_to_show))
    if result.guides_shown:
        from admapper.core.verbosity import is_verbose

        if is_verbose():
            print_info("Manual exploitation guides (BloodHound-style):")
        print_manual_guides_for_keys(result.guides_shown, session=session)

    return result
