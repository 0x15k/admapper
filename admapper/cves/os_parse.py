from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedOs:
    raw: str
    family: str  # workstation | server | unknown
    version: str | None = None  # 7, 2008r2, 2012r2, 2016, 2019, 2022, 10, 11
    build: int | None = None

    @property
    def is_legacy_smb(self) -> bool:
        return self.version in {"7", "2008", "2008r2", "vista", "xp"}

    @property
    def is_server(self) -> bool:
        return self.family == "server"

    @property
    def is_dc_candidate(self) -> bool:
        return self.is_server and self.version in {
            "2008r2",
            "2012",
            "2012r2",
            "2016",
            "2019",
            "2022",
        }


_BUILD_RE = re.compile(r"build\s*(\d+)", re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d+\.\d+)")


def parse_operating_system(os_string: str | None) -> ParsedOs | None:
    if not os_string:
        return None
    raw = os_string.strip()
    lower = raw.lower()

    build_match = _BUILD_RE.search(lower)
    build = int(build_match.group(1)) if build_match else None

    family = "unknown"
    version: str | None = None

    if "server" in lower:
        family = "server"
        for token, label in (
            ("2022", "2022"),
            ("2019", "2019"),
            ("2016", "2016"),
            ("2012 r2", "2012r2"),
            ("2012", "2012"),
            ("2008 r2", "2008r2"),
            ("2008", "2008"),
            ("2003", "2003"),
        ):
            if token in lower:
                version = label
                break
    elif "windows 11" in lower:
        family = "workstation"
        version = "11"
    elif "windows 10" in lower:
        family = "workstation"
        version = "10"
    elif "windows 7" in lower:
        family = "workstation"
        version = "7"
    elif "vista" in lower:
        family = "workstation"
        version = "vista"
    elif "xp" in lower:
        family = "workstation"
        version = "xp"

    if version is None:
        ver_match = _VERSION_RE.search(raw)
        if ver_match and family == "unknown":
            family = "workstation"
            version = ver_match.group(1)

    return ParsedOs(raw=raw, family=family, version=version, build=build)
