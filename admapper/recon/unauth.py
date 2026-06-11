from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from admapper.core.findings import FindingsStore
from admapper.core.hosts import HostsStore
from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_guides_for_keys
from admapper.models.finding import Finding, FindingSeverity
from admapper.models.host import HostRecord
from admapper.recon.dns import discover_domain_dns, dn_to_domain, infer_domain_from_hostname, reverse_ptr
from admapper.recon.ldap_probe import discover_domain_from_ldap, probe_ldap
from admapper.recon.ports import scan_host, scan_hosts, service_name
from admapper.recon.smb_probe import probe_smb_null
from admapper.recon.targets import parse_targets

if TYPE_CHECKING:
    from admapper.core.session import Session

_PROBE_PORTS = (88, 389, 445, 636, 5985, 1433)
_SCAN_TIMEOUT = 3.0
_LDAP_TIMEOUT = 8


@dataclass
class UnauthScanResult:
    domain: str | None
    hosts: list[HostRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    domain_controllers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _resolve_domain(session: Session, hostnames: list[str]) -> str | None:
    if session.workspace and session.workspace.domain:
        return session.workspace.domain
    for name in hostnames:
        inferred = infer_domain_from_hostname(name)
        if inferred:
            return inferred
    return None


def _collect_candidate_ips(session: Session, dns_dcs: list[str]) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    if session.workspace and session.workspace.hosts:
        for ip in parse_targets(session.workspace.hosts):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    for dc in dns_dcs:
        try:
            import dns.resolver

            answers = dns.resolver.resolve(dc, "A")
            for rdata in answers:
                ip = str(rdata)
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        except Exception:
            continue
    return ips


def _enrich_port_map(
    candidate_ips: list[str],
    port_map: dict[str, list[int]],
) -> dict[str, list[int]]:
    """
    Ensure seed targets are probed even when a fast TCP scan returns empty (VPN latency).

    Falls back to LDAP RootDSE / cert SAN — same domain signal as ``nmap -sCV`` on 389.
    """
    enriched = dict(port_map)
    for ip in candidate_ips:
        if enriched.get(ip):
            continue
        # Retry with a longer per-port timeout (sequential — more reliable over VPN)
        open_ports = scan_host(ip, _PROBE_PORTS, timeout=_SCAN_TIMEOUT * 2)
        if open_ports:
            enriched[ip] = open_ports
            continue

        domain, dc_hostname, ldap_probe = discover_domain_from_ldap(ip, timeout=_LDAP_TIMEOUT)
        if ldap_probe and ldap_probe.reachable:
            ports = [ldap_probe.port]
            if 445 not in ports:
                ports.append(445)
            if 88 not in ports:
                ports.append(88)
            enriched[ip] = sorted(set(ports))
            if domain and dc_hostname:
                print_success(f"LDAP identity: {dc_hostname} (domain {domain})")
            elif domain:
                print_success(f"LDAP domain inferred: {domain}")
    return enriched


def _resolve_hostname(
    address: str,
    ldap_results: dict[str, object],
    smb_results: dict[str, object],
) -> str | None:
    smb = smb_results.get(address)
    if smb and getattr(smb, "dns_hostname", None):
        return str(smb.dns_hostname)
    ldap = ldap_results.get(address)
    if ldap and getattr(ldap, "dns_host_name", None):
        return str(ldap.dns_host_name)
    return reverse_ptr(address)


def _build_host_records(
    port_map: dict[str, list[int]],
    ldap_dc_ips: set[str],
    *,
    ldap_results: dict[str, object] | None = None,
    smb_results: dict[str, object] | None = None,
) -> list[HostRecord]:
    ldap_results = ldap_results or {}
    smb_results = smb_results or {}
    records: list[HostRecord] = []
    for address, open_ports in sorted(port_map.items()):
        hostname = _resolve_hostname(address, ldap_results, smb_results)
        roles = sorted({service_name(port) for port in open_ports})
        is_dc = address in ldap_dc_ips or 88 in open_ports and 389 in open_ports
        records.append(
            HostRecord(
                address=address,
                hostname=hostname,
                open_ports=open_ports,
                roles=roles,
                is_domain_controller=is_dc,
            )
        )
    return records


def _findings_from_probes(
    domain: str | None,
    hosts: list[HostRecord],
    ldap_results: dict[str, object],
    smb_results: dict[str, object],
    dns_dcs: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    if domain and dns_dcs:
        findings.append(
            Finding(
                key="dns_domain_controllers",
                title="Domain controllers discovered via DNS SRV",
                severity=FindingSeverity.INFO,
                source="dns_srv",
                detail=", ".join(dns_dcs),
                mitre_id="T1018",
            )
        )
    for host in hosts:
        if host.is_domain_controller:
            findings.append(
                Finding(
                    key=f"dc_detected_{host.address}",
                    title="Domain controller candidate detected",
                    severity=FindingSeverity.INFO,
                    source="port_scan",
                    detail=f"ports={host.open_ports}",
                    mitre_id="T1018",
                    host=host.address,
                )
            )
        ldap = ldap_results.get(host.address)
        if ldap and getattr(ldap, "anonymous_bind", False):
            findings.append(
                Finding(
                    key=f"ldap_anonymous_{host.address}",
                    title="LDAP anonymous bind enabled",
                    severity=FindingSeverity.MEDIUM,
                    source="ldap_probe",
                    detail=getattr(ldap, "default_naming_context", "") or "",
                    mitre_id="T1087.002",
                    host=host.address,
                )
            )
        smb = smb_results.get(host.address)
        if smb and getattr(smb, "null_session", False):
            findings.append(
                Finding(
                    key=f"smb_null_{host.address}",
                    title="SMB null session accepted",
                    severity=FindingSeverity.MEDIUM,
                    source="smb_probe",
                    detail="anonymous login succeeded",
                    mitre_id="T1021.002",
                    host=host.address,
                )
            )
        if 88 in host.open_ports:
            findings.append(
                Finding(
                    key=f"kerberos_open_{host.address}",
                    title="Kerberos service reachable",
                    severity=FindingSeverity.INFO,
                    source="port_scan",
                    detail="tcp/88 open",
                    mitre_id="T1558",
                    host=host.address,
                )
            )
    return findings


def run_unauth_scan(session: Session) -> UnauthScanResult:
    """P02 Unauth discovery — unauthenticated reconnaissance workflow."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    ws_name = session.workspace.name
    hosts_store = HostsStore(session.workspaces, ws_name)
    findings_store = FindingsStore(session.workspaces, ws_name)
    result = UnauthScanResult(domain=session.workspace.domain)

    if not session.workspace.hosts and not session.workspace.domain:
        raise ValueError("set domain <fqdn> and/or set hosts <cidr|ip> before start_unauth")

    from admapper.core.phases import phase_banner
    from admapper.core.verbosity import print_phase, quiet_info, quiet_success, quiet_warning

    print_phase(phase_banner("p02", detail="unauthenticated recon"))
    dns_dcs: list[str] = []
    if session.workspace.domain:
        quiet_info(f"DNS SRV lookup: {session.workspace.domain}")
        dns = discover_domain_dns(session.workspace.domain)
        result.domain = dns.domain
        dns_dcs = dns.domain_controllers
        result.domain_controllers = dns_dcs
        result.errors.extend(dns.errors)
        if dns_dcs:
            quiet_success(f"DCs via DNS: {', '.join(dns_dcs)}")
        elif dns.errors:
            quiet_warning("DNS SRV lookup failed — continuing with host scan")

    candidate_ips = _collect_candidate_ips(session, dns_dcs)
    if not candidate_ips:
        raise ValueError("no scan targets — set hosts <cidr|ip>")

    quiet_info(f"Port scan: {len(candidate_ips)} host(s), ports {list(_PROBE_PORTS)}")
    port_map = scan_hosts(candidate_ips, ports=_PROBE_PORTS, timeout=_SCAN_TIMEOUT)
    port_map = _enrich_port_map(candidate_ips, port_map)
    if not port_map:
        quiet_warning("no hosts with AD services found — check VPN/routing to target")
    else:
        quiet_success(f"responsive hosts: {len(port_map)}")

    ldap_dc_ips: set[str] = set()
    ldap_results: dict[str, object] = {}
    smb_results: dict[str, object] = {}

    for address, open_ports in port_map.items():
        ldap_domain, ldap_host, ldap_best = discover_domain_from_ldap(address, timeout=_LDAP_TIMEOUT)
        if ldap_domain:
            quiet_success(f"LDAP domain: {ldap_domain}" + (f" ({ldap_host})" if ldap_host else ""))
        if ldap_best:
            ldap_results[address] = ldap_best
            if ldap_best.is_domain_controller or ldap_best.default_naming_context:
                ldap_dc_ips.add(address)
            if ldap_best.anonymous_bind:
                quiet_warning(f"LDAP anonymous bind: {address}")
        else:
            for port, use_ssl, label in (
                (389, False, "389"),
                (636, True, "636 (LDAPS)"),
            ):
                if port not in open_ports:
                    continue
                quiet_info(f"LDAP probe: {address}:{label}")
                ldap = probe_ldap(address, port=port, use_ssl=use_ssl, timeout=_LDAP_TIMEOUT)
                prior = ldap_results.get(address)
                if prior is None or (
                    ldap.default_naming_context and not getattr(prior, "default_naming_context", None)
                ):
                    ldap_results[address] = ldap
                if ldap.is_domain_controller or ldap.default_naming_context:
                    ldap_dc_ips.add(address)
                if ldap.anonymous_bind:
                    quiet_warning(f"LDAP anonymous bind: {address}")

        if 445 in open_ports:
            quiet_info(f"SMB probe: {address}:445")
            smb = probe_smb_null(address, port=445)
            smb_results[address] = smb
            if smb.null_session:
                quiet_warning(f"SMB null session: {address}")
                if smb.dns_domain:
                    quiet_success(f"SMB domain: {smb.dns_domain}" + (f" ({smb.dns_hostname})" if smb.dns_hostname else ""))

    hostnames = [h for h in (reverse_ptr(ip) for ip in port_map) if h]
    for ldap in ldap_results.values():
        ctx = getattr(ldap, "default_naming_context", None)
        if ctx and not result.domain:
            result.domain = dn_to_domain(str(ctx))
        if getattr(ldap, "dns_host_name", None):
            hostnames.append(str(ldap.dns_host_name))

    for smb in smb_results.values():
        if getattr(smb, "dns_domain", None) and not result.domain:
            result.domain = str(smb.dns_domain).lower()
        if getattr(smb, "dns_hostname", None):
            hostnames.append(str(smb.dns_hostname))

    if not result.domain:
        for ip in candidate_ips:
            inferred, dc_host, _ = discover_domain_from_ldap(ip, timeout=_LDAP_TIMEOUT)
            if inferred:
                result.domain = inferred
                if dc_host:
                    hostnames.append(dc_host)
                break

    if not result.domain:
        result.domain = _resolve_domain(session, hostnames + dns_dcs)
    if result.domain and session.workspace.domain is None:
        session.set_domain(result.domain)
        print_success(f"domain inferred: {result.domain}")

    host_records = _build_host_records(
        port_map,
        ldap_dc_ips,
        ldap_results=ldap_results,
        smb_results=smb_results,
    )
    result.hosts = hosts_store.merge(host_records)
    result.findings = findings_store.merge(
        _findings_from_probes(result.domain, host_records, ldap_results, smb_results, dns_dcs)
    )

    report_path = session.workspaces.path_for(ws_name) / "unauth_scan.json"
    report_path.write_text(
        json.dumps(
            {
                "domain": result.domain,
                "domain_controllers": result.domain_controllers,
                "hosts": [h.to_dict() for h in result.hosts],
                "findings": [f.to_dict() for f in result.findings],
                "errors": result.errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rows = [
        [
            h.address,
            h.hostname or "-",
            ",".join(str(p) for p in h.open_ports),
            "yes" if h.is_domain_controller else "",
        ]
        for h in result.hosts
    ]
    from admapper.core.verbosity import is_verbose

    if rows and is_verbose():
        print_table(
            "Discovered hosts",
            ["ip", "hostname", "ports", "dc"],
            rows,
        )
    quiet_success(f"findings saved: {len(result.findings)} → findings.json")
    quiet_info(f"report: {report_path}")

    guide_keys: list[str] = []
    if dns_dcs:
        guide_keys.append("dns_domain_controllers")
    for finding in result.findings:
        if finding.key.startswith("ldap_anonymous"):
            guide_keys.append("ldap_anonymous")
        elif finding.key.startswith("smb_null"):
            guide_keys.append("smb_null")
        elif finding.key.startswith("kerberos_open"):
            guide_keys.append("kerberos_open")
    guide_keys.append("ldap_user_enum")
    if guide_keys:
        from admapper.core.verbosity import is_verbose

        if is_verbose():
            print_info("Manual exploitation guides (BloodHound-style):")
        print_manual_guides_for_keys(guide_keys, session=session)

    return result
