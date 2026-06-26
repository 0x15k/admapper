from __future__ import annotations

import ipaddress


def parse_targets(spec: str) -> list[str]:
    """Expand a host spec into a deduplicated list of IP addresses.

    Supports:
    - single IP: ``10.0.0.10``
    - CIDR: ``10.0.0.0/24`` (capped at /24 for safety in unauth scans)
    - comma-separated mix: ``10.0.0.1,10.0.0.2/30``
    """
    addresses: list[str] = []
    seen: set[str] = set()
    for part in spec.replace(";", ",").split(","):
        token = part.strip()
        if not token:
            continue
        if "/" in token:
            network = ipaddress.ip_network(token, strict=False)
            if network.prefixlen < 24:
                network = ipaddress.ip_network(
                    f"{network.network_address}/24",
                    strict=False,
                )
            for host in network.hosts():
                ip = str(host)
                if ip not in seen:
                    seen.add(ip)
                    addresses.append(ip)
            continue
        ip = str(ipaddress.ip_address(token))
        if ip not in seen:
            seen.add(ip)
            addresses.append(ip)
    return addresses
