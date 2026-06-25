from __future__ import annotations

from dataclasses import dataclass, field

from ldap3 import ALL, ANONYMOUS, Connection, Server, SUBTREE
from ldap3.core.exceptions import LDAPException

from admapper.models.user import UserRecord, apply_uac_flags

_USER_FILTER = "(&(objectClass=user)(objectCategory=person))"
_USER_ATTRS = [
    "sAMAccountName",
    "userAccountControl",
    "servicePrincipalName",
    "description",
    "distinguishedName",
    "adminCount",
]


@dataclass
class LdapUserEnumResult:
    host: str
    base_dn: str | None = None
    users: list[UserRecord] = field(default_factory=list)
    error: str | None = None


def _parse_uac(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_spns(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return [str(value)]


def enumerate_users_ldap(
    host: str,
    *,
    port: int = 389,
    base_dn: str | None = None,
    timeout: int = 10,
    use_ssl: bool = False,
) -> LdapUserEnumResult:
    """Enumerate users via anonymous (or pre-bound) LDAP search."""
    result = LdapUserEnumResult(host=host)
    try:
        server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout, get_info=ALL)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)
        if not conn.bind():
            result.error = conn.result.get("description", "bind failed")
            return result
        search_base = base_dn
        if not search_base and server.info:
            search_base = server.info.other.get("defaultNamingContext", [None])[0]
        if not search_base:
            result.error = "could not determine LDAP search base"
            return result
        result.base_dn = search_base
        conn.search(
            search_base=search_base,
            search_filter=_USER_FILTER,
            search_scope=SUBTREE,
            attributes=_USER_ATTRS,
        )
        for entry in conn.entries:
            username = str(entry.sAMAccountName) if entry.sAMAccountName else ""
            if not username:
                continue
            uac = _parse_uac(entry.userAccountControl.value if entry.userAccountControl else None)
            raw_spns = entry.servicePrincipalName.values if entry.servicePrincipalName else None
            spns = _parse_spns(raw_spns)
            admin_count = None
            if hasattr(entry, "adminCount") and entry.adminCount:
                try:
                    admin_count = int(entry.adminCount.value)
                except (ValueError, TypeError):
                    pass
            user = apply_uac_flags(
                UserRecord(
                    username=username,
                    sources=["ldap"],
                    description=str(entry.description) if entry.description else None,
                    dn=str(entry.distinguishedName) if entry.distinguishedName else None,
                    uac=uac,
                    spns=spns,
                    admin_count=admin_count,
                )
            )
            result.users.append(user)
    except LDAPException as exc:
        result.error = str(exc)
    except OSError as exc:
        result.error = str(exc)
    return result
