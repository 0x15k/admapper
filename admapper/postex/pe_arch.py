from __future__ import annotations

import struct
from typing import Literal

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
    """Error 193 = bad PE format — often x64 DLL loaded by x86 host."""
    if "error code: 193" in text.lower():
        return "x86"
    if "error code: 126" in text.lower():
        return None
    return None


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
