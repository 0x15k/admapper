from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from admapper.core.session import Session


def session_owned_users(session: Session) -> list[str]:
    """Owned usernames for the active workspace (empty when no workspace)."""
    if session.workspace is None:
        return []
    return list(session.workspace.owned_users)

# Parser artifacts mistaken for usernames (Kerberos etype lines, etc.)
_INVALID_OWNED_PATTERNS = (
    re.compile(r"^aes\d+", re.I),
    re.compile(r"^krb5", re.I),
    re.compile(r":$"),
    re.compile(r"^ntlm", re.I),
)


def is_valid_owned_username(username: str) -> bool:
    """Filter bogus entries from credential parsers."""
    if not username or not username.strip():
        return False
    name = username.strip()
    if ":" in name and not name.endswith("$"):
        return False
    for pat in _INVALID_OWNED_PATTERNS:
        if pat.search(name):
            return False
    return True


def sanitize_owned_users(users: list[str]) -> tuple[list[str], list[str]]:
    """Return (clean list, removed usernames). Preserves order, dedupes case-insensitively."""
    clean: list[str] = []
    removed: list[str] = []
    seen: set[str] = set()
    for user in users:
        if not is_valid_owned_username(user):
            removed.append(user)
            continue
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        clean.append(user)
    return clean, removed
