from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ldap3 import ALL, SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPException

from admapper.creds.auth_checks import is_protected_user, load_protected_users
from admapper.models.credential import Credential, CredentialType


@dataclass
class LdapSession:
    host: str
    base_dn: str
    conn: Any
    _kerberos_repl: Any = None

    def close(self) -> None:
        if self._kerberos_repl is not None:
            self._kerberos_repl.close()


def _needs_kerberos_ldap(
    cred: Credential,
    *,
    protected_users: set[str] | None,
    force_kerberos: bool = False,
) -> bool:
    if force_kerberos:
        return True
    return is_protected_user(cred.username, protected_users)


def _open_kerberos_ldap_session(
    host: str,
    cred: Credential,
    domain: str,
    *,
    dc_ip: str | None = None,
    ldap_host: str | None = None,
) -> tuple[LdapSession | None, str | None]:
    from admapper.auth.kerberos_ldap_client import start_kerberos_ldap_repl

    try:
        repl = start_kerberos_ldap_repl(
            host,
            cred.username,
            cred.secret,
            domain,
            dc_ip=dc_ip or host,
            ldap_host=ldap_host or host,
        )
        base_dn = repl.base_dn or domain_to_base_dn(domain)
        return (
            LdapSession(
                host=host,
                base_dn=base_dn,
                conn=repl.conn,
                _kerberos_repl=repl,
            ),
            None,
        )
    except Exception as exc:
        return None, str(exc)


def domain_to_base_dn(domain: str) -> str:
    parts = domain.strip().lower().split(".")
    return ",".join(f"DC={part}" for part in parts if part)


def open_ldap_session(
    host: str,
    cred: Credential,
    domain: str,
    *,
    port: int = 389,
    timeout: int = 15,
    use_ssl: bool = False,
    ws_path: str | None = None,
    force_kerberos: bool = False,
) -> tuple[LdapSession | None, str | None]:
    """Authenticated LDAP bind. Returns (session, error)."""
    if cred.cred_type != CredentialType.PASSWORD:
        return None, "authenticated LDAP requires password credential"

    protected = load_protected_users(ws_path)
    from admapper.creds.common import resolve_dc_fqdn

    ldap_host = resolve_dc_fqdn(ws_path, domain, fallback_ip=host)

    if _needs_kerberos_ldap(cred, protected_users=protected, force_kerberos=force_kerberos):
        session, err = _open_kerberos_ldap_session(
            host,
            cred,
            domain,
            dc_ip=host,
            ldap_host=ldap_host,
        )
        if session is not None:
            return session, None
        if force_kerberos or is_protected_user(cred.username, protected):
            return None, err or "Kerberos LDAP bind failed (Protected Users)"

    principal = f"{cred.username}@{domain}"
    try:
        server = Server(
            host,
            port=port,
            use_ssl=use_ssl,
            connect_timeout=timeout,
            get_info=ALL,
        )
        conn = Connection(
            server,
            user=principal,
            password=cred.secret,
            authentication=SIMPLE,
            receive_timeout=timeout,
        )
        if not conn.bind():
            desc = str(conn.result.get("description", "LDAP bind failed"))
            if desc.lower() in {"invalidcredentials", "invalid credentials"}:
                session, err = _open_kerberos_ldap_session(
                    host,
                    cred,
                    domain,
                    dc_ip=host,
                    ldap_host=ldap_host,
                )
                if session is not None:
                    return session, None
            return None, desc
        base_dn = None
        if server.info:
            base_dn = server.info.other.get("defaultNamingContext", [None])[0]
        if not base_dn:
            base_dn = domain_to_base_dn(domain)
        return LdapSession(host=host, base_dn=base_dn, conn=conn), None
    except LDAPException as exc:
        return None, str(exc)
    except OSError as exc:
        return None, str(exc)
