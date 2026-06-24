from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from admapper.auth.auth_enum import run_auth_enumeration
from admapper.auth.ldap_context import fetch_authenticated_user_context
from admapper.core.findings import FindingsStore
from admapper.core.graph import GraphStore
from admapper.core.output import (
    ConfirmLevel,
    confirm,
    print_info,
    print_success,
    print_table,
    print_warning,
)
from admapper.creds.common import pick_dc_ip
from admapper.creds.verify import run_credential_verify
from admapper.models.credential import Credential, CredentialStatus
from admapper.models.finding import Finding, FindingSeverity

if TYPE_CHECKING:
    from admapper.core.session import Session


@dataclass
class AuthStartResult:
    credential: Credential
    owned_user: str
    member_of: list[str] = field(default_factory=list)
    inventory_path: str | None = None
    bloodhound_dir: str | None = None
    errors: list[str] = field(default_factory=list)


def _pick_credential(session: Session, cred_id: str | None) -> Credential:
    store = session.credentials
    if store is None:
        raise RuntimeError("credential store unavailable")
    creds = store.list()
    if not creds:
        raise ValueError("no credentials in workspace — add with creds add or run a cred attack")

    if cred_id:
        cred = next((c for c in creds if c.id == cred_id), None)
        if cred is None:
            raise ValueError(f"credential not found: {cred_id}")
        return cred

    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret:
                return cred
    raise ValueError("no usable credential found")


def _mark_owned_user(session: Session, username: str) -> None:
    if session.workspace is None:
        return
    owned = session.workspace.owned_users
    if username.lower() not in {u.lower() for u in owned}:
        owned.append(username)
    session.workspace.pivot_user = username
    from admapper.analysis.user_match import refresh_workspace_intel

    refresh_workspace_intel(
        session.workspaces.path_for(session.workspace.name),
        users_store=None,
    )
    session.persist_workspace()


def run_start_auth(session: Session, *, cred_id: str | None = None) -> AuthStartResult:
    """Phase 7+8 — verify cred, mark owned, run authenticated enumeration."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.core.discovery import ensure_domain

    domain = ensure_domain(session, announce=False)

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC with LDAP/SMB — run start_unauth first")

    cred = _pick_credential(session, cred_id)
    if not confirm(
        f"Iniciar enum autenticada como {cred.display_user()} @ {dc_ip}?",
        level=ConfirmLevel.WARN,
        mode_auto=session.mode.value == "auto",
        mode_manual=session.mode.value == "manual",
    ):
        print_warning("start_auth cancelado")
        return AuthStartResult(credential=cred, owned_user=cred.username)

    from admapper.core.verbosity import print_phase

    print_phase(f"Phase 7 — credential gate @ {dc_ip}")
    if cred.status != CredentialStatus.VALID:
        verify_result = run_credential_verify(session, cred.id)
        cred = verify_result.credential
        if cred.status != CredentialStatus.VALID:
            raise ValueError(f"credential {cred.id} is not valid — cannot start_auth")

    ws_name = session.workspace.name
    _mark_owned_user(session, cred.username)

    graph_store = GraphStore(session.workspaces, ws_name)
    graph_store.mark_user_owned(domain, cred.username, cred_id=cred.id)
    from admapper.core.provenance import Tool, print_ok

    print_ok(
        f"owned marcado: {domain}\\{cred.username} → graph.json",
        source=Tool.ADMAPPER,
        manual=f"admapper escalate mark {cred.username} -w <workspace>",
    )

    ws_path = str(session.workspaces.path_for(ws_name))
    ldap_ctx = fetch_authenticated_user_context(
        dc_ip,
        cred,
        domain,
        ws_path=ws_path,
    )
    result = AuthStartResult(
        credential=cred,
        owned_user=cred.username,
        member_of=ldap_ctx.member_of,
    )
    if ldap_ctx.error:
        result.errors.append(ldap_ctx.error)
        print_warning(f"user context partial: {ldap_ctx.error}")
    elif ldap_ctx.member_of:
        rows = [[group] for group in ldap_ctx.member_of[:10]]
        print_table("Group memberships (top 10)", ["group_dn"], rows)

    try:
        enum_result = run_auth_enumeration(session, cred, dc_ip, domain)
    except ValueError as exc:
        result.errors.append(str(exc))
        print_warning(f"LDAP enum failed: {exc}")
        enum_result = None

    if enum_result is not None:
        result.inventory_path = enum_result.inventory_path
        result.bloodhound_dir = enum_result.bloodhound_dir
        result.errors.extend(enum_result.ldap.errors)
        if enum_result.smb.error:
            result.errors.append(enum_result.smb.error)

    findings_store = FindingsStore(session.workspaces, ws_name)
    findings_store.merge(
        [
            Finding(
                key=f"owned_user:{cred.username.lower()}",
                title=f"Compromised user: {cred.username}",
                severity=FindingSeverity.HIGH,
                source="start_auth",
                detail=f"domain={domain}, cred_id={cred.id}",
                mitre_id="T1078",
            )
        ]
    )

    report_path = session.workspaces.path_for(ws_name) / "auth_scan.json"
    report_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "dc_ip": dc_ip,
                "credential_id": cred.id,
                "principal": cred.display_user(),
                "owned_user": cred.username,
                "member_of": ldap_ctx.member_of,
                "admin_count": ldap_ctx.admin_count,
                "spns": ldap_ctx.spns,
                "inventory_path": result.inventory_path,
                "bloodhound_dir": result.bloodhound_dir,
                "errors": result.errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print_ok("estado auth guardado → auth_scan.json", source=Tool.ADMAPPER)
    return result
