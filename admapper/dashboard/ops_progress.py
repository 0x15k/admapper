"""Player discoveries during AD Ops — UI must not leak pre-existing workspace facts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PROGRESS_FILE = "ops_progress.json"


@dataclass
class OpsProgress:
    """Facts the operator earned in this ops session (not analyst CLI leftovers)."""

    scan: bool = False
    enum_users: bool = False
    loot: bool = False
    acls: bool = False
    exploit: bool = False
    auth_users: list[str] = field(default_factory=list)
    owned_users: list[str] = field(default_factory=list)
    verified_users: list[str] = field(default_factory=list)
    loot_users: list[str] = field(default_factory=list)
    owned_methods: dict[str, str] = field(default_factory=dict)

    @classmethod
    def fresh(cls) -> OpsProgress:
        return cls()

    @classmethod
    def load(cls, ws_path: Path) -> OpsProgress:
        from admapper.support.owned import is_valid_owned_username, normalize_username, sanitize_owned_users

        path = Path(ws_path) / _PROGRESS_FILE
        if not path.is_file():
            return cls.fresh()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls.fresh()
        prog = cls(
            scan=bool(data.get("scan")),
            enum_users=bool(data.get("enum_users")),
            loot=bool(data.get("loot")),
            acls=bool(data.get("acls")),
            exploit=bool(data.get("exploit")),
            auth_users=list(data.get("auth_users") or []),
            owned_users=list(data.get("owned_users") or []),
            verified_users=list(data.get("verified_users") or []),
            loot_users=list(data.get("loot_users") or []),
            owned_methods=dict(data.get("owned_methods") or {}),
        )
        dirty = False
        for attr in ("auth_users", "owned_users", "verified_users", "loot_users"):
            clean, removed = sanitize_owned_users(list(getattr(prog, attr)))
            if removed:
                setattr(prog, attr, clean)
                dirty = True
        clean_methods: dict[str, str] = {}
        for user, method in prog.owned_methods.items():
            norm = normalize_username(user)
            if norm and is_valid_owned_username(norm):
                clean_methods[norm.lower()] = method
        if clean_methods != prog.owned_methods:
            prog.owned_methods = clean_methods
            dirty = True
        if dirty:
            prog.save(ws_path)
        return prog

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
            "owned_methods": dict(self.owned_methods),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def remember_auth(self, username: str, *, method: str = "password") -> None:
        from admapper.support.owned import is_valid_owned_username, normalize_username

        user = normalize_username(username)
        if not user or not is_valid_owned_username(user):
            return
        key = user.lower()
        for bucket in (self.auth_users, self.owned_users, self.verified_users):
            if key not in {u.lower() for u in bucket}:
                bucket.append(user)
        if key not in self.owned_methods:
            self.owned_methods[key] = method

    def remember_owned(self, username: str, *, method: str) -> None:
        """Mark user as owned with a specific auth method.

        Methods: password, ntlm_hash, spray, kerberoast, asreproast,
                 exploit_acl, dll_hijack, winrm_pth, certificate.
        """
        from admapper.support.owned import is_valid_owned_username, normalize_username

        user = normalize_username(username)
        if not user or not is_valid_owned_username(user):
            return
        key = user.lower()
        if key not in {u.lower() for u in self.owned_users}:
            self.owned_users.append(user)
        # Always update method (later compromise may refine it)
        self.owned_methods[key] = method

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

    def hydrate_from_workspace(self, ws_path: Path) -> None:
        """Promote phase flags from workspace artifacts after a CLI ``admapper run``."""
        root = Path(ws_path)

        def _load(name: str) -> dict:
            path = root / name
            if not path.is_file():
                return {}
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
            return data if isinstance(data, dict) else {}

        unauth = _load("unauth_scan.json")
        state = _load("state.json")
        if unauth.get("hosts") or state.get("domain") or state.get("hosts"):
            self.scan = True
        if _load("auth_scan.json") or _load("auth_inventory.json"):
            self.enum_users = True
        elif _load("users.json").get("users"):
            self.enum_users = True

        loot = _load("loot_manifest.json")
        if loot.get("file_count") or loot.get("parsed_credentials"):
            self.loot = True

        acl = _load("acl_findings.json")
        if acl.get("findings") or acl.get("abuse_paths"):
            self.acls = True

        exploit = _load("exploit_log.json")
        if exploit.get("steps") or exploit.get("gained"):
            self.exploit = True

        postex = _load("postex_ops.json")
        if int(postex.get("opportunity_count") or 0) > 0:
            self.exploit = True


def effective_progress_flags(
    ws_path: Path,
    progress: OpsProgress | None,
) -> dict[str, bool]:
    """Merge ``ops_progress.json`` with on-disk workspace artifacts for UI gating."""
    from admapper.report.engagement import _load_json

    hydrated = OpsProgress.load(ws_path)
    if progress is not None:
        for field in ("scan", "enum_users", "loot", "acls", "exploit"):
            if getattr(progress, field):
                setattr(hydrated, field, True)
        hydrated.owned_users = sorted(
            set(hydrated.owned_users) | set(progress.owned_users),
            key=str.lower,
        )
    hydrated.hydrate_from_workspace(ws_path)

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    state = _load_json(ws_path / "state.json") or {}
    scan = hydrated.scan or bool(unauth.get("hosts")) or bool(state.get("hosts"))
    enum_users = hydrated.enum_users or bool(_load_json(ws_path / "auth_inventory.json"))
    loot_data = _load_json(ws_path / "loot_manifest.json") or {}
    loot = hydrated.loot or bool(loot_data.get("file_count"))
    acl_n = len((_load_json(ws_path / "acl_findings.json") or {}).get("findings") or [])
    acls = hydrated.acls or acl_n > 0
    exploit_log = _load_json(ws_path / "exploit_log.json") or {}
    exploit = hydrated.exploit or bool(exploit_log.get("steps"))

    return {
        "scan": scan,
        "enum_users": enum_users,
        "loot": loot,
        "acls": acls,
        "exploit": exploit,
    }


def filtered_loot_clues(ws_path: Path, progress: OpsProgress | None) -> list[dict[str, str]]:
    """Loot strings after loot phase (workspace-aware, not dashboard-session-only)."""
    from admapper.report.engagement_map import loot_clue_rows

    rows = loot_clue_rows(ws_path)
    if progress is None:
        return rows
    if not effective_progress_flags(ws_path, progress).get("loot"):
        return []
    allowed = {u.lower() for u in progress.loot_users}
    if not allowed:
        return rows
    return [row for row in rows if str(row.get("user", "")).lower() in allowed]
