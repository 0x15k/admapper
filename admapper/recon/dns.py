from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.resolver


SRV_SERVICES = (
    ("_ldap._tcp", "ldap"),
    ("_kerberos._tcp", "kerberos"),
    ("_gc._tcp", "global_catalog"),
    ("_kpasswd._tcp", "kpasswd"),
)


@dataclass
class SrvRecord:
    service: str
    target: str
    port: int
    priority: int
    weight: int

    @property
    def host(self) -> str:
        return self.target.rstrip(".")


@dataclass
class DnsDiscovery:
    domain: str
    srv_records: list[SrvRecord] = field(default_factory=list)
    domain_controllers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _query_srv(domain: str, service: str) -> list[SrvRecord]:
    name = f"{service}.{domain}"
    answers = dns.resolver.resolve(name, "SRV")
    records: list[SrvRecord] = []
    for rdata in answers:
        records.append(
            SrvRecord(
                service=service,
                target=str(rdata.target),
                port=int(rdata.port),
                priority=int(rdata.priority),
                weight=int(rdata.weight),
            )
        )
    return records


def discover_domain_dns(domain: str) -> DnsDiscovery:
    """Resolve AD SRV records for a domain FQDN."""
    result = DnsDiscovery(domain=domain.lower().rstrip("."))
    dc_hosts: set[str] = set()
    for service, _label in SRV_SERVICES:
        try:
            srvs = _query_srv(result.domain, service)
        except (dns.exception.DNSException, OSError) as exc:
            result.errors.append(f"{service}.{result.domain}: {exc}")
            continue
        result.srv_records.extend(srvs)
        for srv in srvs:
            if service == "_ldap._tcp":
                dc_hosts.add(srv.host)
    result.domain_controllers = sorted(dc_hosts)
    return result


def reverse_ptr(ip: str) -> str | None:
    """Best-effort PTR lookup for an IP address."""
    try:
        name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(name, "PTR")
        if answers:
            return str(answers[0]).rstrip(".")
    except (dns.exception.DNSException, OSError):
        return None
    return None


def infer_domain_from_hostname(hostname: str) -> str | None:
    """Extract AD DNS domain from an FQDN (first label = host)."""
    host = hostname.strip().rstrip(".").lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[1:])
    return None


def dn_to_domain(dn: str) -> str | None:
    """Convert LDAP DN (DC=corp,DC=local) to DNS domain (corp.local)."""
    labels: list[str] = []
    for part in dn.split(","):
        piece = part.strip()
        if piece.upper().startswith("DC="):
            labels.append(piece[3:])
    if not labels:
        return None
    return ".".join(labels).lower()
