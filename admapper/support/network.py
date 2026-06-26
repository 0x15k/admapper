from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass

from admapper.support.output import print_info
from admapper.support.platform import is_macos, is_linux

# Common pentest VPN / lab callback ranges (attacker-side tunnels).
_CALLBACK_NETS = (
    re.compile(r"^10\.(10|11|12|13|14|15|16|17|18|19|20)\."),  # common pentest VPN ranges
    re.compile(r"^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\."),  # CGNAT tailscale-like
)

_TUNNEL_IFACE = re.compile(r"^(utun|tun|tap|wg|ppp|nordlynx)", re.I)


@dataclass(frozen=True)
class CallbackCandidate:
    interface: str
    address: str
    score: int


def _is_callback_address(ip: str) -> bool:
    if ip.startswith(("127.", "169.254.", "0.")):
        return False
    return any(p.match(ip) for p in _CALLBACK_NETS)


def _score_candidate(iface: str, ip: str) -> int:
    score = 0
    if _TUNNEL_IFACE.match(iface):
        score += 100
    if iface.lower().startswith("utun"):
        score += 50
    if ip.startswith("10.10."):
        score += 30
    if ip.startswith("10.13."):
        score += 20
    return score


def _parse_darwin_ifconfig(text: str) -> list[CallbackCandidate]:
    out: list[CallbackCandidate] = []
    for block in re.split(r"\n(?=\S)", text):
        first = block.splitlines()[0] if block else ""
        iface = first.split(":")[0].strip()
        if not iface:
            continue
        for match in re.finditer(r"\binet (\d+\.\d+\.\d+\.\d+)(?: --> (\d+\.\d+\.\d+\.\d+))?", block):
            ip = match.group(1)
            if not _is_callback_address(ip):
                continue
            out.append(CallbackCandidate(iface, ip, _score_candidate(iface, ip)))
    return out


def _parse_linux_ip_addr(text: str) -> list[CallbackCandidate]:
    out: list[CallbackCandidate] = []
    iface = ""
    for line in text.splitlines():
        head = re.match(r"^\d+:\s+(\S+?):", line)
        if head:
            iface = head.group(1)
            continue
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", line)
        if not match or not iface:
            continue
        ip = match.group(1)
        if not _is_callback_address(ip):
            continue
        out.append(CallbackCandidate(iface, ip, _score_candidate(iface, ip)))
    return out


def list_callback_candidates() -> list[CallbackCandidate]:
    """Return VPN/tunnel IPv4 addresses suitable as reverse-shell LHOST."""
    try:
        if is_macos():
            proc = subprocess.run(["ifconfig"], capture_output=True, text=True, check=False, timeout=5)
            if proc.returncode != 0:
                return []
            return _parse_darwin_ifconfig(proc.stdout)
        if is_linux():
            proc = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True, check=False, timeout=5)
            if proc.returncode != 0:
                return []
            return _parse_linux_ip_addr(proc.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return []


def resolve_callback_ip(*, exclude: set[str] | None = None) -> str | None:
    """Pick the best VPN/tunnel IP for LHOST (prefers point-to-point interfaces)."""
    import os

    env = os.environ.get("ADMAPPER_LHOST", "").strip()
    if env:
        return env

    skip = exclude or set()
    candidates = [c for c in list_callback_candidates() if c.address not in skip]
    if not candidates:
        return None
    best = max(candidates, key=lambda c: c.score)
    return best.address


def resolve_callback_ip_or_raise(*, exclude: set[str] | None = None) -> str:
    ip = resolve_callback_ip(exclude=exclude)
    if ip:
        return ip
    raise RuntimeError(
        "could not detect VPN callback IP — connect VPN (utun/tun) or set ADMAPPER_LHOST / --lhost"
    )


def log_detected_callback_ip(exclude: set[str] | None = None) -> str:
    """Resolve callback IP and print which interface was chosen."""
    import os

    if os.environ.get("ADMAPPER_LHOST", "").strip():
        ip = os.environ["ADMAPPER_LHOST"].strip()
        print_info(f"callback IP (ADMAPPER_LHOST): {ip}")
        return ip

    skip = exclude or set()
    candidates = [c for c in list_callback_candidates() if c.address not in skip]
    if not candidates:
        raise RuntimeError(
            "could not detect VPN callback IP — connect VPN or pass --lhost / ADMAPPER_LHOST"
        )
    best = max(candidates, key=lambda c: c.score)
    print_info(f"callback IP: {best.address} ({best.interface})")
    return best.address
