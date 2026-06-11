from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from admapper.auth.bloodhound_export import export_bloodhound_minimal
from admapper.auth.ldap_enum import LdapAuthEnumResult, enumerate_ldap_authenticated
from admapper.auth.ldap_session import open_ldap_session
from admapper.auth.smb_enum import SmbAuthEnumResult, enumerate_smb_authenticated
from admapper.core.auth_inventory import AuthInventoryStore
from admapper.core.findings import FindingsStore
from admapper.core.graph import GraphStore
from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.core.users import UsersStore
from admapper.creds.common import apply_cracked_credentials
from admapper.creds.policy import apply_lockout_states, fetch_lockout_context
from admapper.guides.render import print_manual_guide
from admapper.models.credential import Credential
from admapper.models.finding import Finding, FindingSeverity
from admapper.models.spray import DomainLockoutPolicy

if TYPE_CHECKING:
    from admapper.core.session import Session


@dataclass
class AuthEnumResult:
    ldap: LdapAuthEnumResult = field(default_factory=LdapAuthEnumResult)
    smb: SmbAuthEnumResult = field(default_factory=SmbAuthEnumResult)
    inventory_path: str | None = None
    bloodhound_dir: str | None = None


def _merge_graph_inventory(
    graph_store: GraphStore,
    domain: str,
    ldap: LdapAuthEnumResult,
) -> None:
    graph = graph_store.load()
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    existing_ids = {n.get("id") for n in nodes}

    for group in ldap.groups[:200]:
        node_id = f"group:{group.name.lower()}@{domain.lower()}"
        if node_id in existing_ids:
            continue
        nodes.append(
            {
                "id": node_id,
                "type": "group",
                "name": group.name,
                "domain": domain.lower(),
                "owned": False,
            }
        )
        existing_ids.add(node_id)

    for computer in ldap.computers[:200]:
        node_id = f"computer:{computer.name.lower()}.{domain.lower()}"
        if node_id in existing_ids:
            continue
        nodes.append(
            {
                "id": node_id,
                "type": "computer",
                "name": computer.name,
                "domain": domain.lower(),
                "owned": False,
                "unconstrained_delegation": computer.unconstrained_delegation,
            }
        )
        existing_ids.add(node_id)

    graph["nodes"] = nodes
    graph["edges"] = edges
    graph_store.save(graph)


def run_auth_enumeration(
    session: Session,
    cred: Credential,
    dc_ip: str,
    domain: str,
) -> AuthEnumResult:
    """Phase 8 — full authenticated LDAP + SMB enumeration."""
    ws_name = session.workspace.name  # type: ignore[union-attr]
    result = AuthEnumResult()

    from admapper.core.verbosity import print_phase

    print_phase(f"Phase 8 — authenticated LDAP enum @ {dc_ip}")
    ws_path = str(session.workspaces.path_for(ws_name))
    ldap_session, err = open_ldap_session(dc_ip, cred, domain, ws_path=ws_path)
    if ldap_session is None:
        raise ValueError(err or "LDAP session failed")

    ldap_base_dn = ldap_session.base_dn
    try:
        result.ldap = enumerate_ldap_authenticated(ldap_session)
    finally:
        ldap_session.close()
    from admapper.core.provenance import Tool, print_ok, print_warn

    print_ok(
        f"LDAP: {len(result.ldap.users)} users, {len(result.ldap.groups)} groups, "
        f"{len(result.ldap.computers)} computers, {len(result.ldap.delegations)} delegations",
        source=Tool.LDAP,
        manual=f"ldapsearch -H ldap://{dc_ip} -D '{cred.display_user()}' -w '<pass>' -b DC=...",
    )

    print_phase(f"Phase 8 — authenticated SMB enum @ {dc_ip}")
    result.smb = enumerate_smb_authenticated(dc_ip, cred, domain)
    if result.smb.shares:
        print_ok(
            f"SMB shares: {', '.join(result.smb.shares[:12])}",
            source=Tool.IMPACKET,
            manual=f"nxc smb {dc_ip} -u {cred.username} -p '<pass>' -d {domain}",
        )
    if result.smb.error:
        print_warn(f"SMB parcial: {result.smb.error}", source=Tool.IMPACKET)

    users_store = UsersStore(session.workspaces, ws_name)
    if result.ldap.users:
        users_store.merge(result.ldap.users)
    from admapper.intel.user_match import refresh_workspace_intel

    refresh_workspace_intel(ws_path, users_store=users_store)

    if result.smb.gpp_credentials:
        cracked = {
            f"{g.user}@{domain}": g.password for g in result.smb.gpp_credentials
        }
        apply_cracked_credentials(session, domain, cracked, source="gpp")
        rows = [[g.user, g.password, g.source_file] for g in result.smb.gpp_credentials]
        print_table("GPP credentials", ["user", "password", "source"], rows)

    ldap_users = result.ldap.users
    lockout_ctx = fetch_lockout_context(dc_ip, base_dn=ldap_base_dn)
    if lockout_ctx.user_states:
        ldap_users = apply_lockout_states(ldap_users, lockout_ctx.user_states)
    lockout_path = session.workspaces.path_for(ws_name) / "lockout_policy.json"
    lockout_payload = {
        "fetched_at": datetime.now(UTC).isoformat(),
        "host": lockout_ctx.host,
        "base_dn": lockout_ctx.base_dn,
        "error": lockout_ctx.error,
        "policy": (lockout_ctx.policy or DomainLockoutPolicy(source_host=dc_ip)).to_dict(),
        "user_states": [
            {
                "username": s.username,
                "bad_pwd_count": s.bad_pwd_count,
                "lockout_time": s.lockout_time,
            }
            for s in lockout_ctx.user_states
        ],
    }
    lockout_path.write_text(
        json.dumps(lockout_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    inventory = AuthInventoryStore(session.workspaces, ws_name)
    inv_path = inventory.save(
        users=ldap_users,
        groups=result.ldap.groups,
        computers=result.ldap.computers,
        ous=result.ldap.ous,
        gpos=result.ldap.gpos,
        delegations=result.ldap.delegations,
        trusts=result.ldap.trusts,
        gpp_credentials=result.smb.gpp_credentials,
        smb_shares=result.smb.shares,
        adcs_present=result.ldap.adcs_present,
        errors=result.ldap.errors + ([result.smb.error] if result.smb.error else []),
        extra={"smb_signing_required": result.smb.signing_required},
    )
    result.inventory_path = str(inv_path)
    print_ok("inventario guardado → auth_inventory.json", source=Tool.ADMAPPER)

    graph_store = GraphStore(session.workspaces, ws_name)
    _merge_graph_inventory(graph_store, domain, result.ldap)
    print_ok("grafo actualizado → graph.json", source=Tool.ADMAPPER)

    bh_dir = session.workspaces.path_for(ws_name) / "bloodhound"
    export_bloodhound_minimal(
        bh_dir,
        domain=domain,
        users=result.ldap.users,
        groups=result.ldap.groups,
        computers=result.ldap.computers,
    )
    result.bloodhound_dir = str(bh_dir)
    print_ok(
        "export BloodHound → bloodhound/",
        source=Tool.BLOODHOUND,
        manual="bloodhound-python -u user -p pass -d domain -c All -ns <DC>",
    )

    findings = FindingsStore(session.workspaces, ws_name)
    finding_list = [
        Finding(
            key="auth_ldap_inventory",
            title=f"Authenticated LDAP inventory ({len(result.ldap.users)} users)",
            severity=FindingSeverity.INFO,
            source="auth_enum",
            detail=f"groups={len(result.ldap.groups)}, computers={len(result.ldap.computers)}",
            mitre_id="T1087.002",
        )
    ]
    if result.ldap.delegations:
        finding_list.append(
            Finding(
                key="auth_delegations",
                title=f"Delegation findings ({len(result.ldap.delegations)})",
                severity=FindingSeverity.MEDIUM,
                source="auth_enum",
                detail="unconstrained/constrained/RBCD",
                mitre_id="T1558",
            )
        )
    if result.smb.gpp_credentials:
        finding_list.append(
            Finding(
                key="gpp_passwords",
                title=f"GPP credentials ({len(result.smb.gpp_credentials)})",
                severity=FindingSeverity.HIGH,
                source="auth_enum",
                detail="SYSVOL Groups.xml",
                mitre_id="T1552.006",
            )
        )
    if result.ldap.adcs_present:
        finding_list.append(
            Finding(
                key="adcs_detected",
                title="AD CS enrollment service detected",
                severity=FindingSeverity.MEDIUM,
                source="auth_enum",
                mitre_id="T1649",
            )
        )
    findings.merge(finding_list)

    print_manual_guide("auth_enum", session=session)
    return result
