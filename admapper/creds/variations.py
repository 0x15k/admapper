from __future__ import annotations

from datetime import datetime


def generate_spray_variations(domain: str, *, year: int | None = None) -> list[str]:
    """
    Build common enterprise password patterns from the domain FQDN.

    Examples: Winter2026!, Corp123!, Password2026!
    """
    year = year or datetime.now().year
    label = domain.split(".", 1)[0]
    company = label.capitalize()
    company_upper = label.upper()
    seasons = ("Spring", "Summer", "Fall", "Winter", "Autumn")
    months = (
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    )

    candidates = [
        f"{company}{year}!",
        f"{company}{year}",
        f"{company}123!",
        f"{company}123",
        f"{company_upper}{year}!",
        f"Password{year}!",
        f"Welcome{year}!",
        f"Changeme{year}!",
        f"P@ssw0rd{year}!",
        f"{company}@{year}",
    ]
    for season in seasons:
        candidates.append(f"{season}{year}!")
        candidates.append(f"{season}{year}")
    for month in months:
        candidates.append(f"{month}{year}!")
        candidates.append(f"{month}{year}")

    seen: set[str] = set()
    ordered: list[str] = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
