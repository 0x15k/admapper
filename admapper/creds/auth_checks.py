from __future__ import annotations

from dataclasses import dataclass, field

from ldap3 import ALL, NTLM, SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPException

from admapper.models.credential import Credential, CredentialType


@dataclass
class AuthCheckResult:
    ldap: bool | None = None
    smb: bool | None = None
    kerberos: bool | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return any(check is True for check in (self.ldap, self.smb, self.kerberos))

    def is_valid_kerberos_only(self) -> bool:
        return self.kerberos is True


def _ldap_principal(domain: str, username: str, cred_type: CredentialType) -> str:
    if cred_type == CredentialType.NTLM:
        return f"{domain}\\{username}"
    return f"{username}@{domain}"


def check_ldap(
    host: str,
    domain: str,
    username: str,
    secret: str,
    *,
    cred_type: CredentialType = CredentialType.PASSWORD,
    port: int = 389,
    timeout: int = 8,
    use_ssl: bool = False,
) -> bool:
    """Verify credentials with LDAP bind (SIMPLE or NTLM)."""
    principal = _ldap_principal(domain, username, cred_type)
    auth = NTLM if cred_type == CredentialType.NTLM else SIMPLE
    try:
        server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout, get_info=ALL)
        conn = Connection(
            server,
            user=principal,
            password=secret,
            authentication=auth,
            receive_timeout=timeout,
        )
        return bool(conn.bind())
    except (LDAPException, OSError):
        return False


def check_smb(
    host: str,
    domain: str,
    username: str,
    secret: str,
    *,
    cred_type: CredentialType = CredentialType.PASSWORD,
    timeout: int = 8,
) -> bool:
    """Verify credentials with SMB authentication (requires Impacket)."""
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return False

    try:
        smb = SMBConnection(host, host, sess_port=445, timeout=timeout)
        if cred_type == CredentialType.NTLM:
            smb.login(username, "", domain, lmhash="", nthash=secret)
        else:
            smb.login(username, secret, domain)
        return True
    except Exception:
        return False


def check_kerberos_tgt(
    domain: str,
    username: str,
    secret: str,
    *,
    cred_type: CredentialType = CredentialType.PASSWORD,
    dc_ip: str | None = None,
    preferred_clock_skew: str | None = None,
    ws_path: str | None = None,
    kerberos_only: bool = False,
) -> bool:
    """Verify credentials by requesting a Kerberos TGT (requires Impacket)."""
    if cred_type != CredentialType.PASSWORD:
        return False
    try:
        from impacket.krb5 import constants  # noqa: F401
        from impacket.krb5.kerberosv5 import getKerberosTGT  # noqa: F401
        from impacket.krb5.types import Principal  # noqa: F401
    except ImportError:
        return False

    from admapper.support.platform import get_clock_skew
    from admapper.kerberos.skew import check_kerberos_with_skew, seconds_to_faketime_offset
    from admapper.kerberos.time_sync import get_last_ntp_step_seconds, is_clock_unstable

    skew = preferred_clock_skew or get_clock_skew()
    step_seconds = get_last_ntp_step_seconds()
    step_derived = seconds_to_faketime_offset(step_seconds) if step_seconds else None
    from admapper.kerberos.time_sync import was_dc_clock_synced

    skip_system_time = (
        kerberos_only
        and not was_dc_clock_synced(dc_ip)
        and (bool(skew) or is_clock_unstable())
    )
    ok, _applied = check_kerberos_with_skew(
        domain,
        username,
        secret,
        dc_ip=dc_ip,
        preferred_skew=skew,
        step_derived_skew=step_derived,
        ws_path=ws_path,
        skip_system_time=skip_system_time,
    )
    return ok


def is_protected_user(username: str, protected_users: set[str] | None) -> bool:
    if not protected_users:
        return False
    return username.lower() in protected_users


def load_protected_users(ws_path: str | None = None) -> set[str]:
    """Read Protected Users group members from auth_inventory.json."""
    if not ws_path:
        return set()
    from pathlib import Path
    import json

    inv_path = Path(ws_path) / "auth_inventory.json"
    if not inv_path.is_file():
        return set()
    try:
        data = json.loads(inv_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    protected: set[str] = set()
    for group in data.get("groups") or []:
        if str(group.get("name", "")).lower() != "protected users":
            continue
        for member_dn in group.get("members") or []:
            if "CN=" in str(member_dn):
                protected.add(str(member_dn).split(",")[0].replace("CN=", "").lower())
    return protected


def verify_credential_checks(
    cred: Credential,
    dc_ip: str,
    domain: str,
    *,
    timeout: int = 8,
    protected_users: set[str] | None = None,
    ws_path: str | None = None,
) -> AuthCheckResult:
    """Run LDAP, SMB, and Kerberos checks for one credential."""
    result = AuthCheckResult()
    domain_key = (cred.domain or domain).lower()
    username = cred.username
    secret = cred.secret
    kerberos_only = is_protected_user(username, protected_users)

    if cred.cred_type == CredentialType.KERBEROS:
        result.errors.append("kerberos ticket verification not implemented yet")
        return result

    if kerberos_only:
        result.ldap = None
        result.smb = None
    else:
        result.ldap = check_ldap(
            dc_ip,
            domain_key,
            username,
            secret,
            cred_type=cred.cred_type,
            timeout=timeout,
        )
        result.smb = check_smb(
            dc_ip,
            domain_key,
            username,
            secret,
            cred_type=cred.cred_type,
            timeout=timeout,
        )

    result.kerberos = check_kerberos_tgt(
        domain_key,
        username,
        secret,
        cred_type=cred.cred_type,
        dc_ip=dc_ip,
        ws_path=ws_path,
        kerberos_only=kerberos_only,
    )

    if kerberos_only and result.kerberos is True:
        return result

    if result.ldap is False and result.smb is False and result.kerberos is False:
        result.errors.append("all auth checks failed")
    if kerberos_only and result.kerberos is False:
        result.errors.append("Protected Users — Kerberos required (NTLM blocked)")
    if result.smb is False and cred.cred_type == CredentialType.NTLM:
        result.errors.append("SMB NTLM check failed (install impacket: pip install -e '.[recon]')")
    return result
