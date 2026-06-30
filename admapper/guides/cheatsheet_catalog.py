"""Cheatsheet command catalog — imported from New AD Cheatsheet commands.js."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_CATALOG_PATH = Path(__file__).with_name("cheatsheet_catalog.json")


def load_cheatsheet_catalog(path: Path | None = None) -> dict[str, Any]:
    p = path or _CATALOG_PATH
    if not p.is_file():
        return {"phases": []}
    return json.loads(p.read_text(encoding="utf-8"))


def cheatsheet_catalog_json() -> str:
    return json.dumps(load_cheatsheet_catalog(), ensure_ascii=False).replace("<", "\\u003c")


def flat_command_count() -> int:
    data = load_cheatsheet_catalog()
    total = 0
    for phase in data.get("phases") or []:
        for sub in phase.get("subsections") or []:
            total += len(sub.get("commands") or [])
    return total
