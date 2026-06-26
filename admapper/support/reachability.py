from __future__ import annotations

import socket

_DEFAULT_PORTS = (445, 5985)


def check_target_reachable(
    host: str,
    ports: tuple[int, ...] = _DEFAULT_PORTS,
    timeout: float = 3.0,
) -> tuple[bool, str]:
    """Probe common AD remote ports; return (reachable, detail)."""
    errors: list[str] = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, f"tcp/{port} open"
        except OSError as exc:
            errors.append(str(exc))
    return False, errors[0] if errors else "no route"
