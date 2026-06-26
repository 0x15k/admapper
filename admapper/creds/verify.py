from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.creds.auth_checks import verify_credential_checks
from admapper.creds.common import pick_dc_ip
from admapper.models.credential import Credential, CredentialStatus

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class CredentialVerifyResult:
    credential: Credential
    checks: dict[str, bool | None] = field(default_factory=dict)
    status: CredentialStatus = CredentialStatus.INVALID


def run_credential_verify(session: Session, cred_id: str) -> CredentialVerifyResult:
    """P05 Foothold — verify a workspace credential against the domain."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    store = session.credentials
    if store is None:
        raise RuntimeError("credential store unavailable")

    cred = next((c for c in store.list() if c.id == cred_id), None)
    if cred is None:
        raise ValueError(f"credential not found: {cred_id}")

    domain = cred.domain or session.workspace.domain
    if not domain:
        from admapper.support.discovery import ensure_domain

        domain = ensure_domain(session, announce=False)

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC with LDAP/SMB — run start_unauth first")

    from admapper.kerberos.time_sync import ensure_dc_clock, is_clock_unstable, vm_time_sync_warning
    from admapper.kerberos.time_sync import get_last_ntp_step_seconds

    ws_path = session.workspaces.path_for(session.workspace.name)
    ensure_dc_clock(dc_ip, ws_path=ws_path)
    from admapper.support.phases import phase_banner
    from admapper.support.verbosity import print_phase

    print_phase(phase_banner("p05", detail=f"verifying {cred.display_user()} @ {dc_ip}"))
    from admapper.creds.auth_checks import load_protected_users

    protected = load_protected_users(str(ws_path))
    auth_result = verify_credential_checks(
        cred,
        dc_ip,
        domain,
        protected_users=protected,
        ws_path=str(ws_path),
    )

    kerberos_only = cred.username.lower() in protected
    status = (
        CredentialStatus.VALID
        if (auth_result.is_valid_kerberos_only() if kerberos_only else auth_result.is_valid)
        else CredentialStatus.INVALID
    )
    updated = store.mark_status(cred_id, status)
    if updated is None:
        raise RuntimeError(f"failed to update credential status: {cred_id}")

    from admapper.support.verbosity import is_compact

    rows = [
        ["ldap", _status_label(auth_result.ldap)],
        ["smb", _status_label(auth_result.smb)],
        ["kerberos", _status_label(auth_result.kerberos)],
    ]
    if kerberos_only and not is_compact():
        print_info("Protected Users — only Kerberos is accepted for this account")
    print_table("Auth checks", ["method", "result"], rows)

    from admapper.support.platform import get_clock_skew, resolve_faketime
    from admapper.kerberos.skew import faketime_install_hint

    if status == CredentialStatus.VALID:
        if is_compact():
            print_success(f"credential valid: {updated.display_user()}")
        else:
            print_success(f"credential valid: {updated.display_user()} ({updated.id})")
        skew = get_clock_skew()
        if skew and auth_result.kerberos is True and not is_compact():
            print_info(
                f"Kerberos OK with clock skew {skew} — nxc/impacket calls use libfaketime"
            )
        elif auth_result.kerberos is False:
            from admapper.kerberos.time_sync import suggest_time_sync

            skew = get_clock_skew()
            if skew:
                print_warning(
                    f"Kerberos failed at system time but LDAP/SMB OK — "
                    f"clock skew {skew} detected for later tool calls"
                )
            else:
                print_warning(
                    "Kerberos failed (clock skew?) — LDAP/SMB still valid for this user. "
                    f"Sync to DC: {suggest_time_sync(dc_ip)}"
                )
    else:
        if is_compact():
            hint = "kerberos" if auth_result.kerberos is False else "auth"
            print_warning(f"credential invalid: {updated.display_user()} ({hint})")
        else:
            print_warning(f"credential invalid: {updated.display_user()} ({updated.id})")
        for err in auth_result.errors:
            if is_compact() and "Protected Users" in err:
                continue
            print_warning(err)
        if auth_result.kerberos is False and not is_compact():
            from admapper.support.platform import get_clock_skew
            from admapper.kerberos.time_sync import suggest_time_sync

            current_skew = get_clock_skew()
            if current_skew:
                print_warning(
                    f"Kerberos auth failed (using clock skew {current_skew}). "
                    "Confirm the credentials are correct."
                )
            else:
                step_seconds = get_last_ntp_step_seconds()
                if is_clock_unstable() and step_seconds is not None:
                    print_warning(vm_time_sync_warning(step_seconds))
                print_warning(f"fix clock skew: {suggest_time_sync(dc_ip)}")
                if not resolve_faketime():
                    print_warning(
                        f"or per-command offset: {faketime_install_hint()} then --clock-skew '+7h'"
                    )
                elif kerberos_only:
                    print_warning(
                        "Protected Users need Kerberos — install libfaketime if missing, "
                        "or run: admapper exploit --clock-skew '+7h'"
                    )

    return CredentialVerifyResult(
        credential=updated,
        checks={
            "ldap": auth_result.ldap,
            "smb": auth_result.smb,
            "kerberos": auth_result.kerberos,
        },
        status=status,
    )


def _status_label(value: bool | None) -> str:
    if value is True:
        return "valid"
    if value is False:
        return "failed"
    return "skipped"
