from __future__ import annotations

import re
from typing import Any

from admapper.creds.password_variants import password_year_variants

_YEAR_SUFFIX = re.compile(r"(20\d{2})\s*([@!#$%]?)\s*$")
_FILENAME_DATE = re.compile(r"(20\d{2})(\d{4})")  # YYYYMMDD embedded in filename
_FILENAME_YEAR = re.compile(r"(?<![0-9])(20\d{2})(?![0-9])")
_SYMBOL_SUFFIX = re.compile(r"[@!#$%]$")


def _filename_year_hints(source: str) -> list[int]:
    """Years suggested by loot file path/name (not password answers)."""
    years: list[int] = []
    seen: set[int] = set()
    for match in _FILENAME_DATE.finditer(source):
        year = int(match.group(1))
        if year not in seen:
            seen.add(year)
            years.append(year)
    for match in _FILENAME_YEAR.finditer(source):
        year = int(match.group(1))
        if year not in seen:
            seen.add(year)
            years.append(year)
    return years


def _trailing_year(password: str) -> tuple[int | None, str]:
    match = _YEAR_SUFFIX.search(password)
    if not match:
        return None, ""
    return int(match.group(1)), match.group(2)


def analyze_password_clues(clue_rows: list[dict[str, str]]) -> dict[str, Any]:
    """
    Transparent rule engine for loot password strings.

    Returns rules, inferences, and transform *types* — never an ordered password list.
    """
    rules: list[dict[str, Any]] = []
    inferences: list[dict[str, Any]] = []
    possible_transforms: list[dict[str, Any]] = []

    for clue in clue_rows:
        user = str(clue.get("user", ""))
        password = str(clue.get("string", ""))
        source = str(clue.get("source", ""))
        confidence = str(clue.get("confidence", "")).lower()
        verify_state = str(clue.get("verify_state", ""))

        if not user or not password:
            continue

        clue_id = f"{user}:{source or 'loot'}"

        trailing_year, symbol_after_year = _trailing_year(password)
        if trailing_year is not None:
            rules.append(
                {
                    "id": f"{clue_id}:year_suffix",
                    "rule": "year_suffix",
                    "label": "Year suffix in string",
                    "detail": (
                        f"The string ends with year {trailing_year}"
                        + (f" followed by '{symbol_after_year}'" if symbol_after_year else "")
                    ),
                    "user": user,
                    "source": source,
                }
            )
            variant_count = len(password_year_variants(password)) - 1
            if variant_count > 0:
                possible_transforms.append(
                    {
                        "transform": "adjacent_year",
                        "description": (
                            "Try adjacent years to the final suffix "
                            f"(±1..+3 relative to {trailing_year}) — the log might be outdated"
                        ),
                        "user": user,
                        "source": source,
                        "rule_ids": [f"{clue_id}:year_suffix"],
                    }
                )

        file_years = _filename_year_hints(source)
        if trailing_year is not None and file_years:
            for file_year in file_years:
                if file_year == trailing_year:
                    continue
                rules.append(
                    {
                        "id": f"{clue_id}:filename_year_mismatch",
                        "rule": "filename_year_mismatch",
                        "label": "File year ≠ year in string",
                        "detail": (
                            f"The filename suggests {file_year} "
                            f"but the string ends in {trailing_year}"
                        ),
                        "user": user,
                        "source": source,
                    }
                )
                inferences.append(
                    {
                        "label": "Log is newer than password",
                        "reasoning": (
                            f"The file ({source}) references {file_year} while the string "
                            f"retains {trailing_year} — plausible year rotation"
                        ),
                        "user": user,
                        "source": source,
                    }
                )
                possible_transforms.append(
                    {
                        "transform": "replace_trailing_year_with_filename_year",
                        "description": (
                            f"Substitute the final year ({trailing_year}) with the file year ({file_year})"
                        ),
                        "user": user,
                        "source": source,
                        "rule_ids": [f"{clue_id}:filename_year_mismatch"],
                    }
                )
                break

        if _SYMBOL_SUFFIX.search(password):
            sym = password[-1]
            rules.append(
                {
                    "id": f"{clue_id}:symbol_suffix",
                    "rule": "symbol_suffix",
                    "label": "Symbol suffix",
                    "detail": f"The string ends with special character '{sym}'",
                    "user": user,
                    "source": source,
                }
            )
            if trailing_year is not None and not password.endswith("@"):
                possible_transforms.append(
                    {
                        "transform": "append_at_after_year",
                        "description": "Append '@' after the year suffix (common rotation in labs)",
                        "user": user,
                        "source": source,
                        "rule_ids": [f"{clue_id}:year_suffix"],
                    }
                )
            elif trailing_year is not None and password.endswith("@"):
                possible_transforms.append(
                    {
                        "transform": "strip_trailing_symbol",
                        "description": "Remove the trailing '@' and re-evaluate the year suffix",
                        "user": user,
                        "source": source,
                        "rule_ids": [f"{clue_id}:symbol_suffix", f"{clue_id}:year_suffix"],
                    }
                )

        if confidence == "medium":
            rules.append(
                {
                    "id": f"{clue_id}:medium_confidence",
                    "rule": "stale_log",
                    "label": "Medium confidence — log possibly stale",
                    "detail": (
                        "Parser marked medium confidence: may reflect a failed login attempt "
                        "or a stale credential in the log"
                    ),
                    "user": user,
                    "source": source,
                }
            )
            inferences.append(
                {
                    "label": "String not verified automatically",
                    "reasoning": (
                        "Medium confidence: treat the string as a clue, not as a confirmed password"
                    ),
                    "user": user,
                    "source": source,
                }
            )

        if verify_state not in {"", "unverified"} and verify_state != "verified":
            inferences.append(
                {
                    "label": f"Verification status: {verify_state}",
                    "reasoning": "The string from the file does not match a valid credential yet",
                    "user": user,
                    "source": source,
                }
            )

    return {
        "rules": rules,
        "inferences": inferences,
        "possible_transforms": possible_transforms,
    }
