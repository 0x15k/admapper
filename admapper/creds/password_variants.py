from __future__ import annotations

import re


def password_year_variants(password: str) -> list[str]:
    """Try adjacent years when looted passwords embed a stale year."""
    variants = [password]
    match = re.search(r"(20\d{2})\s*$", password)
    if not match:
        return variants
    base_year = int(match.group(1))
    prefix = password[: match.start(1)]
    suffix = password[match.end(1) :]
    for year in range(base_year - 1, base_year + 4):
        candidate = f"{prefix}{year}{suffix}"
        if candidate not in variants:
            variants.append(candidate)
    return variants
