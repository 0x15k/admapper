from __future__ import annotations

from enum import StrEnum

from admapper.core.output import print_info, print_success, print_warning


class Tool(StrEnum):
    """External tool or native admapper module — labels stay in English."""

    ADMAPPER = "admapper"
    NXC = "nxc"
    IMPACKET = "impacket"
    BLOODHOUND = "bloodhound"
    LDAP = "ldap3"
    KRB5 = "krb5"
    FAKETIME = "libfaketime"
    EVIL_WINRM = "evil-winrm"


def _tag(source: Tool) -> str:
    return f"[{source.value}]"


def print_manual(cmd: str) -> None:
    print_info(f"  ↳ manual: {cmd}")


def _maybe_manual(cmd: str | None) -> None:
    """Manual fallbacks only in verbose mode — default output stays methodology-focused."""
    if cmd:
        from admapper.core.verbosity import is_verbose

        if is_verbose():
            print_manual(cmd)


def print_step(message: str, *, source: Tool, manual: str | None = None) -> None:
    print_info(f"{_tag(source)} {message}")
    _maybe_manual(manual)


def print_ok(message: str, *, source: Tool, manual: str | None = None) -> None:
    print_success(f"{_tag(source)} {message}")
    _maybe_manual(manual)


def print_warn(
    message: str,
    *,
    source: Tool | None = None,
    manual: str | None = None,
    always_show_manual: bool = False,
) -> None:
    prefix = f"{_tag(source)} " if source else ""
    print_warning(f"{prefix}{message}")
    if manual and always_show_manual:
        print_manual(manual)
    else:
        _maybe_manual(manual)
