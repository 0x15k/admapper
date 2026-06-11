from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_TASK_NAME_RE = re.compile(r"Task \[([^\]]+)\]", re.IGNORECASE)
_DLL_HIJACK_RE = re.compile(
    r"\.dll|\.zip|scheduled.?task|update.?check|load(?:ing)?\s+[\w.-]+\.dll",
    re.IGNORECASE,
)
_ZIP_DLL_RE = re.compile(r"([\w.-]+\.(?:zip|dll))", re.IGNORECASE)


@dataclass
class LootTaskHint:
    task_name: str
    source_file: str
    line: str


@dataclass
class LootIntelResult:
    task_hints: list[LootTaskHint] = field(default_factory=list)
    dll_hijack_refs: list[str] = field(default_factory=list)
    zip_dll_refs: list[str] = field(default_factory=list)


def scan_loot_directory(loot_dir: Path) -> LootIntelResult:
    """Parse downloaded share loot for scheduled-task / DLL-hijack hints."""
    result = LootIntelResult()
    if not loot_dir.is_dir():
        return result

    for path in sorted(loot_dir.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(loot_dir))
        for line in text.splitlines():
            if not _DLL_HIJACK_RE.search(line):
                continue
            stripped = line.strip()[:200]
            result.dll_hijack_refs.append(f"{rel}: {stripped}")
            if _ZIP_DLL_RE.search(line):
                result.zip_dll_refs.append(f"{rel}: {stripped}")
            task_match = _TASK_NAME_RE.search(line)
            if task_match:
                result.task_hints.append(
                    LootTaskHint(
                        task_name=task_match.group(1).strip(),
                        source_file=rel,
                        line=stripped,
                    )
                )
    return result


def loot_intel_to_dict(data: LootIntelResult) -> dict[str, Any]:
    return {
        "task_hints": [
            {"task_name": h.task_name, "source_file": h.source_file, "line": h.line}
            for h in data.task_hints
        ],
        "dll_hijack_refs": data.dll_hijack_refs[:20],
        "zip_dll_refs": data.zip_dll_refs[:20],
    }
