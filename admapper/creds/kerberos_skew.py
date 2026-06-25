from __future__ import annotations

import json
import sys
from pathlib import Path

from admapper.core.platform import (
    resolve_faketime,
    run_command,
    set_clock_skew,
    tool_install_hint,
)

# Probe offsets when attacker host and domain controller clocks diverge (VPN, TZ, VM snapshots).
_CLOCK_SKEW_CANDIDATES = ("+7h", "+6h", "+8h", "-7h", "+1h", "-1h")

_WORKSPACE_SKEW_FILE = "kerberos_clock.json"


def seconds_to_faketime_offset(seconds: float) -> str:
    """Convert an ntpdate step (seconds) to a libfaketime offset string."""
    if abs(seconds) < 60:
        return f"+{int(round(seconds))}s" if seconds >= 0 else f"{int(round(seconds))}s"
    hours = round(seconds / 3600)
    if hours == 0:
        minutes = round(seconds / 60)
        sign = "+" if minutes >= 0 else ""
        return f"{sign}{minutes}m"
    sign = "+" if hours > 0 else ""
    return f"{sign}{hours}h"


def _skew_store_path(ws_path: str | Path | None) -> Path | None:
    if not ws_path:
        return None
    return Path(ws_path) / _WORKSPACE_SKEW_FILE


def load_workspace_clock_skew(ws_path: str | Path | None) -> str | None:
    """Load a previously working libfaketime offset from the workspace."""
    path = _skew_store_path(ws_path)
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    skew = data.get("skew")
    return str(skew).strip() if skew else None


def save_workspace_clock_skew(
    ws_path: str | Path | None,
    skew: str | None,
    *,
    dc_ip: str | None = None,
    stepped_seconds: float | None = None,
) -> None:
    """Persist a working libfaketime offset for later verify/exploit rounds."""
    path = _skew_store_path(ws_path)
    if path is None:
        return
    if not skew:
        if path.is_file():
            path.unlink(missing_ok=True)
        return
    payload: dict[str, object] = {"skew": skew}
    if dc_ip:
        payload["dc_ip"] = dc_ip
    if stepped_seconds is not None:
        payload["stepped_seconds"] = stepped_seconds
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def apply_workspace_clock_skew(ws_path: str | Path | None) -> str | None:
    """Load workspace skew into the process-global libfaketime offset."""
    skew = load_workspace_clock_skew(ws_path)
    if skew:
        set_clock_skew(skew)
    return skew


def ensure_workspace_skew(ws_path: str | Path | None) -> str | None:
    """Apply cached workspace skew when --clock-skew was not passed on CLI."""
    from admapper.core.platform import get_clock_skew, resolve_faketime

    existing = get_clock_skew()
    if existing:
        return existing
    skew = apply_workspace_clock_skew(ws_path)
    if skew and resolve_faketime():
        from admapper.core.output import print_info

        from admapper.core.provenance import Tool, print_step

        print_step(
            f"Kerberos clock skew: {skew} (workspace kerberos_clock.json)",
            source=Tool.FAKETIME,
            manual=f"faketime -f '{skew}' kinit user@REALM",
        )
    return skew


def _kerberos_subprocess(
    domain: str,
    username: str,
    secret: str,
    *,
    dc_ip: str | None,
    clock_skew: str | None = None,
    timeout: int = 15,
) -> bool:
    """Request a TGT in a child process (optionally under libfaketime)."""
    script = (
        "from impacket.krb5 import constants\n"
        "from impacket.krb5.kerberosv5 import getKerberosTGT\n"
        "from impacket.krb5.types import Principal\n"
        f"user = {username!r}\n"
        f"secret = {secret!r}\n"
        f"domain = {domain!r}\n"
        f"dc_ip = {dc_ip!r}\n"
        "p = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)\n"
        "getKerberosTGT(p, secret, domain, lmhash='', nthash='', aesKey=None, kdcHost=dc_ip)\n"
    )
    cmd = [sys.executable, "-c", script]
    if clock_skew:
        faketime = resolve_faketime()
        if not faketime:
            return False
        cmd = [faketime, "-f", clock_skew, *cmd]
    try:
        proc = run_command(cmd, timeout=timeout, use_clock_skew=False)
        return proc.returncode == 0
    except Exception:
        return False


def _probe_candidates(
    preferred_skew: str | None,
    *,
    step_derived_skew: str | None = None,
) -> list[str]:
    candidates: list[str] = []
    for skew in (preferred_skew, step_derived_skew):
        if skew and skew not in candidates:
            candidates.append(skew)
    for skew in _CLOCK_SKEW_CANDIDATES:
        if skew not in candidates:
            candidates.append(skew)
    return candidates


def check_kerberos_with_skew(
    domain: str,
    username: str,
    secret: str,
    *,
    dc_ip: str | None,
    preferred_skew: str | None = None,
    step_derived_skew: str | None = None,
    ws_path: str | Path | None = None,
    skip_system_time: bool = False,
) -> tuple[bool, str | None]:
    """
    Try Kerberos TGT; on failure probe libfaketime offsets.

    Returns (success, applied_skew).
    """
    workspace_skew = load_workspace_clock_skew(ws_path)
    effective_preferred = preferred_skew or workspace_skew

    # Always try real clock first — sntp may have synced even if user passed --clock-skew.
    if not skip_system_time:
        if _kerberos_subprocess(domain, username, secret, dc_ip=dc_ip):
            if effective_preferred:
                from admapper.core.output import print_info

                set_clock_skew(None)
                save_workspace_clock_skew(ws_path, None)
                print_info(
                    "Kerberos OK at system time — ignoring --clock-skew "
                    "(clock already synced to DC)"
                )
            return True, None

    faketime = resolve_faketime()
    if not faketime:
        return False, None

    # Try to query clock skew via LDAP to append a highly precise candidate
    ldap_derived_skew = None
    if dc_ip:
        from admapper.creds.time_sync import calculate_ldap_clock_skew
        try:
            ldap_skew_seconds = calculate_ldap_clock_skew(dc_ip)
            if ldap_skew_seconds is not None:
                ldap_derived_skew = seconds_to_faketime_offset(ldap_skew_seconds)
        except Exception:
            pass

    candidates = _probe_candidates(
        effective_preferred,
        step_derived_skew=step_derived_skew or ldap_derived_skew,
    )

    for skew in candidates:
        if _kerberos_subprocess(domain, username, secret, dc_ip=dc_ip, clock_skew=skew):
            set_clock_skew(skew)
            save_workspace_clock_skew(ws_path, skew, dc_ip=dc_ip)
            return True, skew
    return False, None


def faketime_install_hint() -> str:
    return tool_install_hint("faketime")


def apply_clock_skew_option(clock_skew: str | None) -> None:
    """Set global libfaketime offset when --clock-skew is passed on CLI."""
    if not clock_skew:
        return
    from admapper.core.output import print_info, print_warning

    if resolve_faketime():
        set_clock_skew(clock_skew)
        print_info(f"Kerberos clock skew: {clock_skew} (libfaketime)")
    else:
        print_warning(f"libfaketime not found — {faketime_install_hint()}")
