from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from admapper.core.platform import is_linux, is_macos, subprocess_run_kwargs

# ntpdate steps larger than this suggest VM guest time sync is fighting manual sync.
_LARGE_STEP_THRESHOLD_SEC = 3600

_dc_clock_state: dict[str, object] = {
    "synced_dc": None,
    "unstable": False,
    "last_step_seconds": None,
    "sync_attempts": 0,
}


def reset_dc_clock_state() -> None:
    """Clear per-process clock sync state (tests)."""
    _dc_clock_state.update(
        synced_dc=None,
        unstable=False,
        last_step_seconds=None,
        sync_attempts=0,
    )


def is_clock_unstable() -> bool:
    return bool(_dc_clock_state.get("unstable"))


def get_last_ntp_step_seconds() -> float | None:
    value = _dc_clock_state.get("last_step_seconds")
    return float(value) if value is not None else None


def was_dc_clock_synced(dc_ip: str | None = None) -> bool:
    """True when ensure_dc_clock successfully synced to this DC in-process."""
    synced = _dc_clock_state.get("synced_dc")
    if not synced:
        return False
    if dc_ip and str(synced) != str(dc_ip):
        return False
    return not bool(_dc_clock_state.get("unstable"))


def _sntp_binary() -> str | None:
    from admapper.core.platform import resolve_executable

    return resolve_executable(["sntp"])


def _sntp_available() -> bool:
    return _sntp_binary() is not None


def _resolve_linux_ntp_binary() -> str | None:
    """Return the first NTP client on PATH: ntpdate, then ntpsec-ntpdate (Kali)."""
    for binary in ("ntpdate", "ntpsec-ntpdate"):
        if shutil.which(binary):
            return binary
    return None


def _run_sync_command(cmd: list[str], *, timeout: int, ok_prefix: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            **subprocess_run_kwargs(),
        )
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if proc.returncode == 0:
            return True, f"{ok_prefix}: {output}" if output else ok_prefix
        return False, output or f"{' '.join(cmd)} exited {proc.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"{' '.join(cmd)} timed out"
    except OSError as exc:
        return False, str(exc)


def parse_ntp_step_seconds(output: str) -> float | None:
    """Parse ntpdate/ntpsec-ntpdate 'time stepped by N sec' from command output."""
    for pattern in (
        r"time stepped by\s+([+-]?[0-9]+(?:\.[0-9]+)?)\s+sec",
        r"step(?:ped)?\s+time\s+server\s+offset\s+([+-]?[0-9]+(?:\.[0-9]+)?)\s+sec",
        r"offset\s+([+-]?[0-9]+(?:\.[0-9]+)?)\s+sec",
    ):
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                continue
    return None


def vm_time_sync_warning(step_seconds: float) -> str:
    hours = abs(step_seconds) / 3600
    return (
        f"ntpdate stepped clock by {step_seconds:+.0f}s (~{hours:.1f}h) — "
        "if this repeats every sync, VM guest time sync is likely reverting the clock "
        "(disable VMware/VirtualBox 'sync time with host' or use libfaketime)"
    )


def sync_time_to_dc(dc_ip: str, *, timeout: int = 30) -> tuple[bool, str]:
    """
    Sync local system clock to the domain controller.

    Linux/Kali: ``sudo ntpdate <DC>`` or ``sudo ntpsec-ntpdate <DC>``, then ``sntp``.
    macOS: ``sudo sntp -sS <DC>``.
    """
    if is_linux():
        ntp_binary = _resolve_linux_ntp_binary()
        if ntp_binary:
            ok, detail = _run_sync_command(
                ["sudo", ntp_binary, dc_ip],
                timeout=timeout,
                ok_prefix=f"{ntp_binary} synced to {dc_ip}",
            )
            if ok:
                return True, detail

    sntp_bin = _sntp_binary()
    if sntp_bin:
        ok, detail = _run_sync_command(
            ["sudo", sntp_bin, "-sS", dc_ip],
            timeout=timeout,
            ok_prefix=f"sntp synced to {dc_ip}",
        )
        if ok:
            offset = _parse_sntp_offset(detail)
            if offset:
                detail += f" (offset {offset})"
            return True, detail

    if is_macos():
        return False, "sntp not found — brew install does not apply; use system sntp"
    return (
        False,
        "install ntpdate, ntpsec-ntpdate (Debian/Kali: apt install ntpsec-ntpdate), "
        "or sntp to sync clock with the DC",
    )


def ensure_dc_clock(
    dc_ip: str | None,
    *,
    enabled: bool = True,
    ws_path: str | Path | None = None,
    force: bool = False,
) -> bool:
    """
    Auto-sync host clock to the DC before Kerberos (sudo ntpdate/ntpsec-ntpdate/sntp).

    Called by scan/run/exploit/verify — operator should not sync the clock manually.
    On failure or unstable VM clocks, Kerberos paths fall back to libfaketime auto-probe.
    """
    from admapper.core.output import print_info, print_success, print_warning
    from admapper.core.platform import get_clock_skew, set_clock_skew
    from admapper.creds.kerberos_skew import apply_workspace_clock_skew

    if not dc_ip:
        return False

    cached_skew = apply_workspace_clock_skew(ws_path)
    if not enabled:
        return bool(cached_skew)

    explicit_skew = get_clock_skew()
    if cached_skew:
        from admapper.core.provenance import Tool, print_step

        print_step(
            f"usando clock skew Kerberos en caché {cached_skew} (workspace)",
            source=Tool.FAKETIME,
        )
    elif explicit_skew:
        print_info(
            f"using Kerberos clock skew {explicit_skew} (--clock-skew); skipping ntpdate"
        )

    unstable = is_clock_unstable()
    already_synced = _dc_clock_state.get("synced_dc") == dc_ip
    skew_active = bool(cached_skew or explicit_skew)
    if not force and (skew_active or (unstable and already_synced)):
        if unstable and already_synced and not skew_active:
            print_info(
                "skipping ntpdate — clock marked unstable (VM time sync); "
                "Kerberos will use libfaketime"
            )
        return skew_active or unstable

    _dc_clock_state["sync_attempts"] = int(_dc_clock_state.get("sync_attempts") or 0) + 1

    print_info(f"syncing clock with DC {dc_ip} …")
    ok, detail = sync_time_to_dc(dc_ip)
    if ok:
        step_seconds = parse_ntp_step_seconds(detail)
        if step_seconds is not None:
            _dc_clock_state["last_step_seconds"] = step_seconds
            if abs(step_seconds) >= _LARGE_STEP_THRESHOLD_SEC:
                _dc_clock_state["unstable"] = True
                print_warning(vm_time_sync_warning(step_seconds))
                from admapper.creds.kerberos_skew import (
                    save_workspace_clock_skew,
                    seconds_to_faketime_offset,
                )

                derived = seconds_to_faketime_offset(step_seconds)
                if not get_clock_skew():
                    set_clock_skew(derived)
                    save_workspace_clock_skew(
                        ws_path,
                        derived,
                        dc_ip=dc_ip,
                        stepped_seconds=step_seconds,
                    )
                    print_info(
                        f"large clock step — pre-setting libfaketime offset {derived} for Kerberos"
                    )
            else:
                _dc_clock_state["unstable"] = False
                if not get_clock_skew():
                    set_clock_skew(None)
        else:
            if not get_clock_skew():
                set_clock_skew(None)
        _dc_clock_state["synced_dc"] = dc_ip
        if not _dc_clock_state.get("unstable"):
            from admapper.creds.kerberos_skew import save_workspace_clock_skew

            set_clock_skew(None)
            save_workspace_clock_skew(ws_path, None)
        print_success(detail)
        return True

    print_warning(f"clock sync failed: {detail}")
    print_info("continuing — Kerberos will auto-probe libfaketime if needed")
    return False


def _parse_sntp_offset(output: str) -> str | None:
    match = re.search(r"([+-]?\d+\.?\d*)\s+[+/-]", output)
    if not match:
        return None
    try:
        seconds = float(match.group(1))
        hours = seconds / 3600
        return f"{hours:+.1f}h"
    except ValueError:
        return match.group(1)


def suggest_time_sync(dc_ip: str) -> str:
    if is_macos():
        return f"sudo sntp -sS {dc_ip}"
    if is_linux():
        ntp_binary = _resolve_linux_ntp_binary()
        if ntp_binary:
            return f"sudo {ntp_binary} {dc_ip}"
    if _sntp_available():
        return f"sudo sntp -sS {dc_ip}"
    return f"sync system clock to {dc_ip} (Kerberos requires <5 min skew)"
