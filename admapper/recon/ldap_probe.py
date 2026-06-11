from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from ldap3 import ALL, ANONYMOUS, BASE, SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPException

from admapper.recon.dns import dn_to_domain, infer_domain_from_hostname


@dataclass
class LdapProbeResult:
    host: str
    port: int
    reachable: bool = False
    anonymous_bind: bool = False
    default_naming_context: str | None = None
    naming_contexts: list[str] = field(default_factory=list)
    dns_host_name: str | None = None
    domain_functionality: str | None = None
    error: str | None = None

    @property
    def is_domain_controller(self) -> bool:
        return bool(self.dns_host_name and self.default_naming_context)


def _apply_rootdse_entry(result: LdapProbeResult, entry: object) -> None:
    for attr, target in (
        ("defaultNamingContext", "default_naming_context"),
        ("dnsHostName", "dns_host_name"),
        ("domainFunctionality", "domain_functionality"),
    ):
        raw = getattr(entry, attr, None)
        if raw is None:
            continue
        value = str(raw.value if hasattr(raw, "value") else raw)
        setattr(result, target, value)
    naming = getattr(entry, "namingContexts", None)
    if naming is not None:
        values = naming.values if hasattr(naming, "values") else naming
        result.naming_contexts = [str(v) for v in values]


def _fetch_rootdse_search(conn: Connection, result: LdapProbeResult) -> None:
    """RootDSE via base search — works when anonymous bind is denied but reading is allowed."""
    try:
        if not conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["defaultNamingContext", "dnsHostName", "namingContexts", "domainFunctionality"],
        ):
            return
        if not conn.entries:
            return
        _apply_rootdse_entry(result, conn.entries[0])
    except LDAPException:
        return


def _apply_rootdse(result: LdapProbeResult, info: object | None) -> None:
    if info is None:
        return
    other = getattr(info, "other", {}) or {}
    result.default_naming_context = other.get("defaultNamingContext", [None])[0]
    result.naming_contexts = list(getattr(info, "naming_contexts", None) or [])
    result.dns_host_name = other.get("dnsHostName", [None])[0]
    result.domain_functionality = other.get("domainFunctionality", [None])[0]


def domain_from_tls_certificate(
    host: str,
    *,
    port: int = 636,
    timeout: float = 5.0,
) -> tuple[str | None, str | None]:
    """
    Read AD DNS domain from the LDAPS certificate (same signal as nmap ldap ssl-cert).
    Returns (domain, dc_hostname).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except OSError:
        return None, None

    hostnames: list[str] = []
    for _typ, value in cert.get("subjectAltName") or ():
        if _typ == "DNS" and value:
            hostnames.append(str(value).rstrip(".").lower())
    for rdn in cert.get("subject") or ():
        for key, value in rdn:
            if key == "commonName" and value:
                hostnames.append(str(value).rstrip(".").lower())

    dc_hostname = hostnames[0] if hostnames else None
    domain: str | None = None
    for name in hostnames:
        inferred = infer_domain_from_hostname(name)
        if inferred and "." in inferred:
            domain = inferred
            if name.startswith("dc"):
                dc_hostname = name
            break
    return domain, dc_hostname


def probe_ldap(
    host: str,
    *,
    port: int = 389,
    timeout: int = 8,
    use_ssl: bool = False,
) -> LdapProbeResult:
    """LDAP RootDSE collection; anonymous bind is optional on hardened DCs."""
    result = LdapProbeResult(host=host, port=port)
    try:
        server = Server(
            host,
            port=port,
            use_ssl=use_ssl,
            connect_timeout=timeout,
            get_info=ALL,
        )
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)
        if not conn.open():
            result.error = str(conn.last_error or "LDAP open failed")
            return result
        result.reachable = True
        if conn.bind():
            result.anonymous_bind = True
        else:
            result.error = str(conn.result.get("description", "bind failed"))
        if server.info:
            _apply_rootdse(result, server.info)
        if not result.default_naming_context:
            _fetch_rootdse_search(conn, result)
        if not result.default_naming_context and not result.dns_host_name:
            try:
                server.refresh_server_info(conn)
                _apply_rootdse(result, server.info)
            except LDAPException:
                pass
    except LDAPException as exc:
        result.error = str(exc)
    except OSError as exc:
        result.error = str(exc)
    return result


def discover_domain_from_ldap(
    host: str,
    *,
    timeout: int = 8,
) -> tuple[str | None, str | None, LdapProbeResult | None]:
    """
    Infer AD domain from RootDSE and/or LDAPS certificate without credentials.
    Returns (domain, dc_hostname, best_ldap_probe).
    """
    best: LdapProbeResult | None = None
    domain: str | None = None
    dc_hostname: str | None = None

    cert_domain, cert_host = domain_from_tls_certificate(host, port=636, timeout=float(timeout))
    if cert_domain:
        domain = cert_domain
        dc_hostname = cert_host

    for port, use_ssl in ((389, False), (636, True)):
        probe = probe_ldap(host, port=port, use_ssl=use_ssl, timeout=timeout)
        if probe.reachable and (best is None or probe.default_naming_context):
            best = probe
        if probe.default_naming_context:
            domain = dn_to_domain(str(probe.default_naming_context)) or domain
        if probe.dns_host_name:
            dc_hostname = str(probe.dns_host_name).lower()
            domain = infer_domain_from_hostname(dc_hostname) or domain
        if domain:
            break

    return domain, dc_hostname, best


def discover_domain_from_bind(
    host: str,
    username: str,
    password: str,
    *,
    domain_hint: str | None = None,
    timeout: int = 8,
) -> str | None:
    """Infer DNS domain from RootDSE after a credentialed LDAP/LDAPS bind."""
    from admapper.recon.dns import dn_to_domain

    principals: list[str] = []
    if domain_hint:
        principals.append(f"{username}@{domain_hint}")
        principals.append(f"{domain_hint}\\{username}")
    principals.append(username)

    for port, use_ssl in ((389, False), (636, True)):
        for principal in principals:
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
                    password=password,
                    authentication=SIMPLE,
                    receive_timeout=timeout,
                )
                if not conn.bind():
                    continue
                ctx = server.info.other.get("defaultNamingContext", [None])[0] if server.info else None
                if ctx:
                    return dn_to_domain(str(ctx))
            except (LDAPException, OSError):
                continue
    return None
