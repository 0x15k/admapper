from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from admapper.support.platform import (
    default_wordlist_paths,
    resolve_hashcat,
    resolve_john,
    run_command,
    tool_install_hint,
)


def find_wordlist(candidates: list[Path | str] | None = None) -> Path | None:
    """Return the first existing wordlist from cross-platform common locations."""
    paths = [Path(p) for p in (candidates or [])] + default_wordlist_paths()
    for path in paths:
        if path.is_file():
            return path
    return None


def crack_with_hashcat(
    hash_file: Path,
    wordlist: Path,
    *,
    mode: int = 18200,
    timeout: int = 120,
) -> dict[str, str]:
    """Attempt offline crack with hashcat. Returns username -> password."""
    hashcat = resolve_hashcat()
    if not hashcat:
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        potfile = Path(tmp) / "potfile"
        outfile = Path(tmp) / "cracked.txt"
        cmd = [
            hashcat,
            "-m",
            str(mode),
            "-a",
            "0",
            str(hash_file),
            str(wordlist),
            "--potfile-path",
            str(potfile),
            "-o",
            str(outfile),
            "--quiet",
        ]
        try:
            run_command(cmd, timeout=timeout)
            show_cmd = [
                hashcat,
                "-m",
                str(mode),
                str(hash_file),
                "--show",
                "--potfile-path",
                str(potfile),
            ]
            show = run_command(show_cmd, timeout=30)
        except (subprocess.TimeoutExpired, OSError):
            return {}
        cracked: dict[str, str] = {}
        for line in (show.stdout or "").splitlines():
            if ":" not in line:
                continue
            user_part, password = line.split(":", 1)
            if password.startswith("$krb5asrep$"):
                continue
            cracked[user_part] = password
        return cracked


def crack_with_john(
    hash_file: Path,
    wordlist: Path,
    *,
    timeout: int = 120,
) -> dict[str, str]:
    """Attempt offline crack with john. Returns username -> password."""
    john = resolve_john()
    if not john:
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp) / "admapper_john"
        cmd = [
            john,
            f"--wordlist={wordlist}",
            f"--session={session.name}",
            str(hash_file),
        ]
        try:
            run_command(cmd, timeout=timeout)
            show = run_command(
                [john, "--show", f"--session={session.name}", str(hash_file)],
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            return {}
        cracked: dict[str, str] = {}
        for line in (show.stdout or "").splitlines():
            if ":" not in line or line.startswith("0 password hashes"):
                continue
            user_part, password = line.split(":", 1)
            cracked[user_part] = password
        return cracked


def missing_cracker_hint() -> str:
    """Message when neither hashcat nor john is available."""
    return f"hashcat: {tool_install_hint('hashcat')} | john: {tool_install_hint('john')}"
