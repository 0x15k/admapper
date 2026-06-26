from __future__ import annotations

import re

from admapper.postex.hijack_intel import parse_schtasks_list_output

_DROP_LINE = re.compile(
    r"^(Evil-WinRM shell|Info:|Warning:|Error:|\*Evil-WinRM\*|#<|.*quoting_detection_proc.*|"
    r"Data: |Payload: |^\s*:\s*$)",
    re.IGNORECASE,
)
_HIJACK_BODY = re.compile(
    r"\.zip|\.dll|Task\s*\[|ProgramData|loaded\s+|No updates",
    re.IGNORECASE,
)


def strip_evil_winrm_output(text: str) -> str:
    """Remove evil-winrm banners and keep command output."""
    if not text.strip():
        return ""
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if lines:
                lines.append("")
            continue
        if _DROP_LINE.search(stripped):
            continue
        if stripped.startswith("Export-ModuleMember"):
            continue
        lines.append(line)

    body = "\n".join(lines).strip()
    if "TaskName:" in body:
        parsed = parse_schtasks_list_output(body)
        if parsed.strip():
            return parsed
    return body


def extract_winrm_command_body(text: str) -> str:
    """Strip evil-winrm noise but keep monitor/task lines the strict stripper may drop."""
    strict = strip_evil_winrm_output(text)
    if strict and (_HIJACK_BODY.search(strict) or len(strict.splitlines()) >= 3):
        return strict
    kept: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if _DROP_LINE.search(stripped):
            continue
        if stripped.startswith("Evil-WinRM"):
            continue
        kept.append(raw.rstrip())
    body = "\n".join(kept).strip()
    if "TaskName:" in body:
        parsed = parse_schtasks_list_output(body)
        if parsed.strip():
            return parsed
    return body
