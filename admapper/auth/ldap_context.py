from __future__ import annotations

from dataclasses import dataclass, field

from ldap3 import SUBTREE

from admapper.auth.ldap_session import open_ldap_session
from admapper.models.credential import Credential, CredentialType


@dataclass
class AuthenticatedUserContext:
    username: str
    domain: str
    member_of: list[str] = field(default_factory=list)
    admin_count: int | None = None
    spns: list[str] = field(default_factory=list)
    error: str | None = None


def fetch_authenticated_user_context(
    host: str,
    cred: Credential,
    domain: str,
    *,
    port: int = 389,
    timeout: int = 10,
    ws_path: str | None = None,
) -> AuthenticatedUserContext:
    """Lightweight LDAP enum for the authenticated user (Phase 7 bridge to Phase 8)."""
    result = AuthenticatedUserContext(username=cred.username, domain=domain)
    if cred.cred_type != CredentialType.PASSWORD:
        result.error = "authenticated LDAP context requires password credential"
        return result

    ldap_session, err = open_ldap_session(
        host,
        cred,
        domain,
        port=port,
        timeout=timeout,
        ws_path=ws_path,
    )
    if ldap_session is None:
        result.error = err or "bind failed"
        return result

    try:
        ldap_session.conn.search(
            search_base=ldap_session.base_dn,
            search_filter=f"(sAMAccountName={cred.username})",
            search_scope=SUBTREE,
            attributes=["memberOf", "adminCount", "servicePrincipalName"],
        )
        if not ldap_session.conn.entries:
            result.error = "authenticated user object not found"
            return result

        entry = ldap_session.conn.entries[0]
        if getattr(entry, "memberOf", None):
            result.member_of = [str(v) for v in entry.memberOf.values]
        if getattr(entry, "adminCount", None):
            try:
                result.admin_count = int(entry.adminCount.value)
            except (TypeError, ValueError):
                result.admin_count = None
        if getattr(entry, "servicePrincipalName", None):
            result.spns = [str(v) for v in entry.servicePrincipalName.values]
    except Exception as exc:
        result.error = str(exc)
    finally:
        ldap_session.close()
    return result
