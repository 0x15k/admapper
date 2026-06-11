"""Local operator prep hints — clock, hosts, libfaketime (no sudo from game UI)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from admapper.core.platform import is_macos, resolve_faketime
from admapper.creds.kerberos_skew import load_workspace_clock_skew
from admapper.creds.time_sync import suggest_time_sync, was_dc_clock_synced


def build_operator_setup(
    ws_path: Path,
    *,
    dc_ip: str,
    dc_host: str,
) -> dict[str, Any]:
    """Facts + copy-paste commands for the machine running admapper (not the lab)."""
    dc_ip = dc_ip.strip()
    dc_host = dc_host.strip().rstrip(".")
    skew = load_workspace_clock_skew(ws_path)
    faketime_ok = bool(resolve_faketime())
    hosts_entry = ""
    if dc_ip and dc_host and dc_host not in {"-", "?", "sin PTR"}:
        hosts_entry = f"{dc_ip}  {dc_host}"

    clock_ok = bool(skew) or (dc_ip and was_dc_clock_synced(dc_ip))
    install_faketime = (
        "brew install libfaketime" if is_macos() else "sudo apt install faketime"
    )

    notes: list[str] = []
    if not clock_ok and not faketime_ok:
        notes.append(
            "Kerberos puede fallar hasta sincronizar reloj o instalar libfaketime."
        )
    elif skew:
        notes.append(f"Offset Kerberos en workspace: {skew} (libfaketime).")
    elif clock_ok:
        notes.append("Reloj sincronizado con el DC en esta sesión.")
    if hosts_entry:
        notes.append("Añade la línea de hosts si LDAP/Kerberos resuelven mal el FQDN.")

    return {
        "clock_ready": clock_ok,
        "kerberos_skew": skew,
        "libfaketime_installed": faketime_ok,
        "hosts_entry": hosts_entry or None,
        "sync_clock_cmd": suggest_time_sync(dc_ip) if dc_ip else None,
        "install_faketime_cmd": install_faketime,
        "sync_dc_cmd": (
            f"admapper sync-dc -H {dc_ip}" if dc_ip else None
        ),
        "notes": notes,
    }
