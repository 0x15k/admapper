from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from admapper.creds.password_variants import password_year_variants


@dataclass(frozen=True)
class PasswordCandidate:
    password: str
    reason: str
    source_password: str | None = None


def propose_password_candidates(
    password: str,
    *,
    stale_log: bool = False,
    confidence: str = "medium",
) -> list[PasswordCandidate]:
    """
    Build ordered password candidates for spray/verify — tool proposes, operator validates.

    Reasons:
      - parsed_from_loot: exact string from file
      - year_variant: adjacent year (log may embed stale 20xx)
      - stale_log_hint: log documents INVALID_CREDENTIALS / bind failure
      - symbol_suffix: common AD rotation (@ on trailing year)
    """
    seen: set[str] = set()
    out: list[PasswordCandidate] = []

    def add(pwd: str, reason: str, *, source: str | None = None) -> None:
        if not pwd or pwd in seen:
            return
        seen.add(pwd)
        out.append(PasswordCandidate(pwd, reason, source_password=source))

    add(password, "parsed_from_loot")

    if re.search(r"20\d{2}\s*$", password):
        for variant in password_year_variants(password):
            tag = "year_variant"
            if stale_log and variant != password:
                tag = "stale_log_year_variant"
            add(variant, tag, source=password)
        if not password.endswith("@"):
            add(f"{password}@", "symbol_suffix", source=password)
        base = password.rstrip("@")
        if base != password:
            for variant in password_year_variants(base):
                add(f"{variant}@", "symbol_suffix_year", source=password)

    if stale_log and confidence == "medium":
        add(password, "stale_log_hint")

    return out


def build_password_candidates_file(ws_path: Path) -> Path:
    """Persist proposed passwords per loot user + verification status from credentials.json."""
    manifest_path = ws_path / "loot_manifest.json"
    cred_path = ws_path / "credentials.json"
    out_path = ws_path / "password_candidates.json"

    manifest = {}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    cred_data = json.loads(cred_path.read_text(encoding="utf-8")) if cred_path.is_file() else {}
    verified: dict[str, set[str]] = {}
    for cred in cred_data.get("credentials") or []:
        user = str(cred.get("username", "")).lower()
        secret = str(cred.get("secret", ""))
        if str(cred.get("status")) == "valid" and user and secret:
            verified.setdefault(user, set()).add(secret)

    entries: list[dict] = []
    for item in manifest.get("parsed_credentials") or []:
        username = str(item.get("username", ""))
        password = str(item.get("password", ""))
        if not username or not password:
            continue
        stale = str(item.get("confidence", "")).lower() == "medium"
        for cand in propose_password_candidates(
            password,
            stale_log=stale,
            confidence=str(item.get("confidence", "")),
        ):
            entries.append(
                {
                    "username": username,
                    "password": cand.password,
                    "reason": cand.reason,
                    "source_password": cand.source_password,
                    "source_file": item.get("source_file"),
                    "verified": cand.password in verified.get(username.lower(), set()),
                    "wordlist_line": f"{username}:{cand.password}",
                }
            )

    payload = {
        "candidate_count": len(entries),
        "candidates": entries,
        "wordlist": sorted({e["wordlist_line"] for e in entries}),
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path
