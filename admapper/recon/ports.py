from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

AD_PORTS: tuple[int, ...] = (88, 389, 445, 636, 3268, 3269, 5985, 1433)

_PORT_SERVICE = {
    88: "kerberos",
    389: "ldap",
    445: "smb",
    636: "ldaps",
    3268: "gc",
    3269: "gcs",
    5985: "winrm",
    1433: "mssql",
}


def service_name(port: int) -> str:
    return _PORT_SERVICE.get(port, f"tcp/{port}")


def is_port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_host(host: str, ports: tuple[int, ...] = AD_PORTS, timeout: float = 1.5) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        if is_port_open(host, port, timeout=timeout):
            open_ports.append(port)
    return open_ports


def scan_hosts(
    hosts: list[str],
    ports: tuple[int, ...] = AD_PORTS,
    *,
    timeout: float = 1.5,
    max_workers: int = 32,
) -> dict[str, list[int]]:
    """Concurrent TCP connect scan across many hosts."""
    results: dict[str, list[int]] = {}

    def _scan_one(ip: str) -> tuple[str, list[int]]:
        return ip, scan_host(ip, ports, timeout=timeout)

    worker_count = min(max_workers, max(1, len(hosts)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {pool.submit(_scan_one, host): host for host in hosts}
        for future in as_completed(futures):
            ip, open_ports = future.result()
            if open_ports:
                results[ip] = sorted(open_ports)
    return results
