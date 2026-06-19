"""Player discoveries during AD Ops — UI must not leak pre-existing workspace facts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PROGRESS_FILE = "game_progress.json"


@dataclass
class GameProgress:
    """Facts the operator earned in this game session (not analyst CLI leftovers)."""

    scan: bool = False
    enum_users: bool = False
    loot: bool = False
    acls: bool = False
    exploit: bool = False
    auth_users: list[str] = field(default_factory=list)
    owned_users: list[str] = field(default_factory=list)
    verified_users: list[str] = field(default_factory=list)
    loot_users: list[str] = field(default_factory=list)

    @classmethod
    def fresh(cls) -> GameProgress:
        return cls()

    @classmethod
    def load(cls, ws_path: Path) -> GameProgress:
        path = Path(ws_path) / _PROGRESS_FILE
        if not path.is_file():
            return cls.fresh()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls.fresh()
        return cls(
            scan=bool(data.get("scan")),
            enum_users=bool(data.get("enum_users")),
            loot=bool(data.get("loot")),
            acls=bool(data.get("acls")),
            exploit=bool(data.get("exploit")),
            auth_users=list(data.get("auth_users") or []),
            owned_users=list(data.get("owned_users") or []),
            verified_users=list(data.get("verified_users") or []),
            loot_users=list(data.get("loot_users") or []),
        )

    def save(self, ws_path: Path) -> None:
        path = Path(ws_path) / _PROGRESS_FILE
        payload: dict[str, Any] = {
            "scan": self.scan,
            "enum_users": self.enum_users,
            "loot": self.loot,
            "acls": self.acls,
            "exploit": self.exploit,
            "auth_users": sorted(set(self.auth_users), key=str.lower),
            "owned_users": sorted(set(self.owned_users), key=str.lower),
            "verified_users": sorted(set(self.verified_users), key=str.lower),
            "loot_users": sorted(set(self.loot_users), key=str.lower),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def remember_auth(self, username: str) -> None:
        user = username.strip()
        if not user:
            return
        key = user.lower()
        for bucket in (self.auth_users, self.owned_users, self.verified_users):
            if key not in {u.lower() for u in bucket}:
                bucket.append(user)

    def remember_loot_users(self, usernames: list[str]) -> None:
        self.loot = True
        for name in usernames:
            user = str(name).strip()
            if user and user.lower() not in {u.lower() for u in self.loot_users}:
                self.loot_users.append(user)

    def verified_set(self) -> set[str]:
        return {u.lower() for u in self.verified_users}

    def owned_set(self) -> set[str]:
        return {u.lower().rstrip("$") for u in self.owned_users}


def filtered_loot_clues(ws_path: Path, progress: GameProgress | None) -> list[dict[str, str]]:
    """Loot strings only after the player ran loot in this game session."""
    from admapper.report.engagement_map import loot_clue_rows

    if progress is None:
        return loot_clue_rows(ws_path)
    if not progress.loot:
        return []
    allowed = {u.lower() for u in progress.loot_users}
    return [
        row
        for row in loot_clue_rows(ws_path)
        if str(row.get("user", "")).lower() in allowed
    ]
