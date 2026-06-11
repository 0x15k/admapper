from __future__ import annotations

from dataclasses import dataclass

from admapper.models.credential import Credential, CredentialType


@dataclass
class DomainCveContext:
    machine_account_quota: int | None = None
    domain_controllers: list[str] | None = None
    error: str | None = None


def enumerate_domain_cve_context(
    cred: Credential,
    domain: str,
    dc_ip: str,
) -> DomainCveContext:
    """LDAP domain policy for noPac prerequisites (MAQ)."""
    result = DomainCveContext()
    if cred.cred_type != CredentialType.PASSWORD:
        result.error = "domain CVE enum requires password credential"
        return result

    try:
        from ldap3 import ALL, SUBTREE, Connection, Server
    except ImportError:
        result.error = "ldap3 not installed"
        return result

    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=10)
        user = f"{domain}\\{cred.username}"
        conn = Connection(server, user=user, password=cred.secret, auto_bind=True)
        base_dn = ",".join(f"DC={part}" for part in domain.split("."))

        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=domainDNS)",
            search_scope=SUBTREE,
            attributes=["msDS-MachineAccountQuota"],
        )
        if conn.entries:
            entry = conn.entries[0]
            if hasattr(entry, "msDS_MachineAccountQuota"):
                raw = entry.msDS_MachineAccountQuota.value
                if raw is not None:
                    result.machine_account_quota = int(raw)

        conn.search(
            search_base=base_dn,
            search_filter="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            search_scope=SUBTREE,
            attributes=["dNSHostName", "sAMAccountName"],
        )
        dcs: list[str] = []
        for entry in conn.entries:
            dns = str(getattr(entry, "dNSHostName", "") or "")
            name = str(getattr(entry, "sAMAccountName", "") or "").rstrip("$")
            host = dns or name
            if host:
                dcs.append(host)
        result.domain_controllers = sorted(dcs)
        conn.unbind()
    except Exception as exc:
        result.error = str(exc)
    return result
