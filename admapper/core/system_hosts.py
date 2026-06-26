from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from admapper.core.platform import is_windows, subprocess_run_kwargs

_HOSTS_MARKER = "# admapper"


class HostsSyncStatus(str, Enum):
    PRESENT = "present"
    ADDED = "added"
    UPDATED = "updated"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class HostsSyncResult:
    status: HostsSyncStatus
    ip: str
    hostname: str
    detail: str = ""
    previous_ip: str | None = None


def system_hosts_path() -> Path:
    override = os.environ.get("ADMAPPER_HOSTS_FILE", "").strip()
    if override:
        return Path(override)
    return Path("/etc/hosts")


def _valid_hostname(hostname: str) -> bool:
    hostname = hostname.strip().rstrip(".")
    if not hostname or hostname in {"-", "sin PTR"}:
        return False
    return bool(re.match(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$", hostname))


def _parse_line(line: str) -> tuple[str, list[str]] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split()
    if len(parts) < 2:
        return None
    return parts[0], parts[1:]


def _find_hostname_line(lines: list[str], hostname: str) -> int | None:
    host_lower = hostname.lower()
    for idx, line in enumerate(lines):
        parsed = _parse_line(line)
        if not parsed:
            continue
        _ip, names = parsed
        if any(name.lower() == host_lower for name in names):
            return idx
    return None


def _build_entry_line(ip: str, hostname: str) -> str:
    return f"{ip}  {hostname}\n"


def _apply_entry(lines: list[str], ip: str, hostname: str) -> tuple[list[str], HostsSyncStatus, str | None]:
    """Return updated lines, status, and previous IP if updated."""
    idx = _find_hostname_line(lines, hostname)
    if idx is not None:
        parsed = _parse_line(lines[idx])
        assert parsed is not None
        old_ip, names = parsed
        if old_ip == ip and hostname in names:
            return lines, HostsSyncStatus.PRESENT, None
        new_line = _build_entry_line(ip, hostname)
        if old_ip != ip:
            return [*lines[:idx], new_line, *lines[idx + 1 :]], HostsSyncStatus.UPDATED, old_ip
        return [*lines[:idx], new_line, *lines[idx + 1 :]], HostsSyncStatus.PRESENT, None

    for line in lines:
        parsed = _parse_line(line)
        if not parsed:
            continue
        line_ip, names = parsed
        if line_ip == ip and hostname in names:
            return lines, HostsSyncStatus.PRESENT, None

    block: list[str] = []
    if not any(_HOSTS_MARKER in line for line in lines):
        if lines and lines[-1].strip():
            block.append("\n")
        block.append(f"{_HOSTS_MARKER}\n")
    block.append(_build_entry_line(ip, hostname))
    return [*lines, *block], HostsSyncStatus.ADDED, None


def _write_hosts_file(path: Path, content: str, *, use_sudo: bool) -> None:
    if is_windows():
        raise OSError("automatic /etc/hosts sync is not supported on Windows")

    if not use_sudo:
        path.write_text(content, encoding="utf-8")
        return

    # Try non-interactive sudo first (works if cached or NOPASSWD)
    proc = subprocess.run(
        ["sudo", "-n", "tee", str(path)],
        input=content,
        capture_output=True,
        text=True,
        check=False,
        **subprocess_run_kwargs(),
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise PermissionError(err or "sudo tee /etc/hosts failed")


def ensure_system_hosts_entry(
    ip: str,
    hostname: str,
    *,
    use_sudo: bool = True,
    hosts_path: Path | None = None,
) -> HostsSyncResult:
    """Ensure ``ip hostname`` exists in the system hosts file (target respawn-safe)."""
    ip = ip.strip()
    hostname = hostname.strip().rstrip(".")
    if not ip or not _valid_hostname(hostname):
        return HostsSyncResult(
            HostsSyncStatus.SKIPPED,
            ip,
            hostname,
            detail="invalid ip or hostname",
        )

    path = hosts_path or system_hosts_path()
    if not path.is_file():
        return HostsSyncResult(
            HostsSyncStatus.FAILED,
            ip,
            hostname,
            detail=f"{path} not found",
        )

    try:
        original = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return HostsSyncResult(
            HostsSyncStatus.FAILED,
            ip,
            hostname,
            detail=str(exc),
        )

    lines = original.splitlines(keepends=True)
    if not lines:
        lines = [""]

    new_lines, status, previous_ip = _apply_entry(lines, ip, hostname)
    if status == HostsSyncStatus.PRESENT:
        return HostsSyncResult(status, ip, hostname)

    new_content = "".join(new_lines)
    if not new_content.endswith("\n"):
        new_content += "\n"

    try:
        _write_hosts_file(path, new_content, use_sudo=use_sudo)
    except (OSError, PermissionError) as exc:
        return HostsSyncResult(
            HostsSyncStatus.FAILED,
            ip,
            hostname,
            detail=str(exc),
        )

    return HostsSyncResult(status, ip, hostname, previous_ip=previous_ip)


def format_hosts_sync_message(result: HostsSyncResult) -> str:
    if result.status == HostsSyncStatus.PRESENT:
        return f"/etc/hosts OK — {result.ip}  {result.hostname}"
    if result.status == HostsSyncStatus.ADDED:
        return f"/etc/hosts updated — added {result.ip}  {result.hostname}"
    if result.status == HostsSyncStatus.UPDATED:
        prev = result.previous_ip or "?"
        return (
            f"/etc/hosts updated — {result.hostname}: {prev} → {result.ip} "
            "(machine respawned)"
        )
    if result.status == HostsSyncStatus.SKIPPED:
        return f"/etc/hosts skipped — {result.detail}"
    return f"/etc/hosts failed — {result.detail}"


def hosts_entry_exists(
    ip: str,
    hostname: str,
    *,
    hosts_path: Path | None = None,
) -> bool:
    """Read-only check: does ``ip  hostname`` already exist in /etc/hosts?"""
    ip = ip.strip()
    hostname = hostname.strip().rstrip(".")
    if not ip or not _valid_hostname(hostname):
        return False
    path = hosts_path or system_hosts_path()
    if not path.is_file():
        return False
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return False
    idx = _find_hostname_line(lines, hostname)
    if idx is None:
        return False
    parsed = _parse_line(lines[idx])
    if parsed is None:
        return False
    return parsed[0] == ip
