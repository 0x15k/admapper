from __future__ import annotations

import re

# WINRM <host> <port> <label> <message...>
_NXC_WINRM_LINE = re.compile(r"^\s*WINRM\s+\S+\s+\d+\s+\S+\s+(.*)$", re.IGNORECASE)
_NXC_GENERIC_LINE = re.compile(r"^\s*\S+\s+\S+\s+\d+\s+\S+\s+(.*)$")

_SKIP_MSG_PREFIXES = (
    "[*]",
    "[-]",
    "[+] logging",
)
_SKIP_MSG_CONTAINS = ("(Pwn3d!)",)


def _keep_message(msg: str) -> bool:
    if not msg:
        return False
    for prefix in _SKIP_MSG_PREFIXES:
        if msg.startswith(prefix):
            return False
    for needle in _SKIP_MSG_CONTAINS:
        if needle in msg:
            return False
    if msg.startswith("[+] Executed command"):
        # nxc 1.4: output may trail after colon
        if ":" in msg:
            tail = msg.split(":", 1)[1].strip()
            return bool(tail) and not tail.startswith("(")
        return False
    return True


def strip_nxc_winrm_output(output: str) -> str:
    """Extract command output from netexec winrm log lines (incl. nxc 1.4)."""
    lines: list[str] = []
    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = _NXC_WINRM_LINE.match(line) or _NXC_GENERIC_LINE.match(line)
        if not match:
            lines.append(line)
            continue
        msg = match.group(1).strip()
        if msg.startswith("[+] Executed command") and ":" in msg:
            tail = msg.split(":", 1)[1].strip()
            if tail and not tail.startswith("("):
                lines.append(tail)
            continue
        if _keep_message(msg):
            lines.append(msg)
    return "\n".join(lines).strip()
