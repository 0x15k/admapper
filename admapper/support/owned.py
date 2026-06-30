from __future__ import annotations

import re

# Parser artifacts mistaken for usernames (Kerberos etype lines, etc.)
_INVALID_OWNED_PATTERNS = (
    re.compile(r"^aes\d+", re.I),
    re.compile(r"^krb5", re.I),
    re.compile(r":$"),
    re.compile(r"^ntlm", re.I),
)


def normalize_username(username: str) -> str:
    """Extract sAMAccountName from UI/parser noise (user / pass, DOMAIN\\user)."""
    name = str(username or "").strip()
    if not name:
        return ""
    if " /" in name:
        name = name.split(" /", 1)[0].strip()
    if "\\" in name:
        name = name.rsplit("\\", 1)[-1].strip()
    if "@" in name:
        name = name.split("@", 1)[0].strip()
    return name.strip().rstrip("/]").strip()


def is_valid_owned_username(username: str) -> bool:
    """Filter bogus entries from credential parsers."""
    if not username or not username.strip():
        return False
    name = normalize_username(username)
    if not name:
        return False
    if " /" in str(username) or str(username).strip().endswith(("/", "/]", " /")):
        return False
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
        normalized = normalize_username(user)
        if not is_valid_owned_username(normalized):
            removed.append(user)
            continue
        key = normalized.lower()
        if key in seen:
            removed.append(user)
            continue
        seen.add(key)
        clean.append(normalized)
    return clean, removed
