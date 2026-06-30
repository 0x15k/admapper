from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from admapper.winrm.client import WinRMClient

TargetArch = Literal["x86", "x64"]

_PE_MACHINE = {
    0x014C: "x86",
    0x8664: "x64",
}


def arch_from_pe_bytes(data: bytes) -> TargetArch | None:
    if len(data) < 0x40:
        return None
    if data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 6 > len(data):
        return None
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    return _PE_MACHINE.get(machine)  # type: ignore[return-value]


def normalize_arch(value: str | None) -> TargetArch | None:
    if not value:
        return None
    v = value.lower().strip()
    if v in {"x86", "i386", "i686", "32", "win32"}:
        return "x86"
    if v in {"x64", "amd64", "x86_64", "64"}:
        return "x64"
    return None


def infer_arch_from_monitor_log(text: str) -> TargetArch | None:
    """Infer payload arch from service/monitor log lines.

    Error 193 (%1 is not a valid Win32 application) means PE bitness mismatch —
    an x64 DLL loaded into a 32-bit applier fails with 193, so prefer x86.
    """
    low = text.lower()
    if "error code: 193" in low or "not a valid win32 application" in low:
        return "x86"
    if "error code: 126" in low:
        return None
    return None


def _service_exe_guesses(drop_path: str) -> list[str]:
    product = drop_path.rstrip("\\/").split("\\")[-1]
    if not product:
        return []
    return [
        rf"C:\Program Files\{product}\{product}.exe",
        rf"C:\Program Files\{product}\bin\{product}.exe",
        rf"C:\Program Files (x86)\{product}\{product}.exe",
    ]


def ps_read_pe_arch_script(exe_path: str) -> str:
    safe = exe_path.strip('"').replace("'", "''")
    return (
        f"$p='{safe}';"
        "if(-not(Test-Path -LiteralPath $p)){Write-Output 'unknown';exit};"
        "$b=[IO.File]::ReadAllBytes($p);"
        "if($b.Length -lt 64 -or $b[0] -ne 77 -or $b[1] -ne 90){Write-Output 'unknown';exit};"
        "$pe=[BitConverter]::ToInt32($b,0x3c);"
        "if($pe -le 0 -or $pe+6 -ge $b.Length){Write-Output 'unknown';exit};"
        "$m=[BitConverter]::ToUInt16($b,$pe+4);"
        "if($m -eq 0x8664){'x64'}elseif($m -eq 0x014c){'x86'}else{'unknown'}"
    )


def is_dc_target(scan: dict, ws_path: Path | None = None) -> bool:
    """True when the hijack target is (likely) a domain controller."""
    if scan.get("dc_ip"):
        return True
    if not ws_path:
        return False
    unauth_path = ws_path / "unauth_scan.json"
    if not unauth_path.is_file():
        return False
    try:
        data = json.loads(unauth_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    for host in data.get("hosts") or []:
        if host.get("is_domain_controller"):
            return True
    return False


def resolve_payload_arch(
    finding: dict,
    scan: dict,
    *,
    client: WinRMClient | None = None,
    arch_override: TargetArch | None = None,
    ws_path: Path | None = None,
) -> tuple[TargetArch, str]:
    """Choose msfvenom/mingw arch with an operator-visible reason string."""
    monitor_text = str(scan.get("monitor_log_excerpt") or "")
    if client is not None:
        drop = str(finding.get("drop_path") or r"C:\ProgramData")
        drop_stripped = drop.rstrip("\\")
        for rel in (
            r"\Logs\monitor.log",
            r"\Logs\app.log",
            r"\Logs\service.log",
            r"\Logs\error.log",
            r"\monitor.log",
            r"\app.log",
            r"\service.log",
        ):
            path = f"{drop_stripped}{rel}"
            safe = path.replace("'", "''")
            try:
                from admapper.winrm.client import WinRMError

                proc = client.execute(
                    f"if(Test-Path -LiteralPath '{safe}')"
                    f"{{Get-Content -LiteralPath '{safe}' -Tail 30}}",
                    shell="powershell",
                )
                live = (proc.stdout or "").strip()
                if live:
                    monitor_text = live
                    break
            except WinRMError:
                pass

    arch_hint = infer_arch_from_monitor_log(monitor_text)
    if arch_hint:
        if arch_override and arch_override != arch_hint:
            reason = f"monitor log error 193 → {arch_hint} (ignoring cli --arch {arch_override})"
        else:
            reason = "monitor log PE mismatch hint (error 193)"
        return arch_hint, reason

    if arch_override:
        return arch_override, "cli --arch override"

    scan_arch = normalize_arch(str(finding.get("target_arch") or ""))
    dc_target = is_dc_target(scan, ws_path)
    if scan_arch and not (scan_arch == "x86" and dc_target):
        return scan_arch, "postex_scan target_arch"

    exe = str(finding.get("executable") or "").strip().strip('"')
    if client is not None and exe.lower().endswith(".exe"):
        try:
            from admapper.winrm.client import WinRMError

            proc = client.execute(ps_read_pe_arch_script(exe), shell="powershell")
            arch = normalize_arch((proc.stdout or "").strip())
            if arch:
                return arch, f"remote PE arch ({exe})"
        except WinRMError:
            pass

    if client is not None:
        drop = str(finding.get("drop_path") or "")
        for guess in _service_exe_guesses(drop):
            try:
                from admapper.winrm.client import WinRMError

                proc = client.execute(ps_read_pe_arch_script(guess), shell="powershell")
                arch = normalize_arch((proc.stdout or "").strip())
                if arch:
                    return arch, f"remote PE arch ({guess})"
            except WinRMError:
                pass

    if is_dc_target(scan, ws_path):
        return "x64", "DC target (default x64; ignored stale scan x86)" if scan_arch == "x86" else "DC target (default x64)"

    return "x86", "default x86 (32-bit service loaders common for DLL hijack)"


def parse_privilege_output(text: str) -> set[str]:
    """Return enabled privilege names from ``whoami /priv`` output."""
    privs: set[str] = set()
    for line in text.splitlines():
        if "privilege" in line.lower() and "description" in line.lower():
            continue
        match = re.search(r"(Se[A-Za-z]+Privilege)", line)
        if not match:
            continue
        if "disabled" in line.lower():
            continue
        privs.add(match.group(1))
    return privs
