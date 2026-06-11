from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from admapper.core.users import UsersStore
from admapper.models.user import UserRecord


@dataclass
class MatchedUser:
    username: str
    sources: list[str] = field(default_factory=list)
    in_domain: bool = False
    cred_status: str | None = None
    loot_password: str | None = None
    description: str | None = None

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "sources": self.sources,
            "in_domain": self.in_domain,
            "cred_status": self.cred_status,
            "loot_password": self.loot_password,
            "description": self.description,
        }


def _load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _best_cred_status(credentials: list[dict], username: str) -> str | None:
    user_l = username.lower()
    status_rank = {"valid": 3, "invalid": 2, "unverified": 1}
    best: tuple[int, str] | None = None
    for cred in credentials:
        if str(cred.get("username", "")).lower() != user_l:
            continue
        status = str(cred.get("status", "unverified"))
        rank = status_rank.get(status, 0)
        if best is None or rank > best[0]:
            best = (rank, status)
    return best[1] if best else None


def sync_loot_users(users_store: UsersStore, manifest: dict) -> None:
    """Merge loot-discovered usernames into users.json for cross-source matching."""
    loot_users: list[UserRecord] = []
    for item in manifest.get("parsed_credentials") or []:
        username = str(item.get("username", "")).strip()
        if not username:
            continue
        loot_users.append(
            UserRecord(
                username=username,
                sources=["share_loot"],
                description=f"loot:{item.get('source_file', '')}"[:120] or None,
            )
        )
    if loot_users:
        users_store.merge(loot_users)


def _normalize_bh_username(name: str) -> str:
    """BloodHound Properties.name is often USER@DOMAIN."""
    base = name.split("@", 1)[0]
    return base.lower()


def _merge_sources(entry: MatchedUser, *sources: str) -> None:
    entry.sources = sorted(set(entry.sources) | {s for s in sources if s})


def build_user_intel(ws_path: Path) -> dict:
    """Cross-match LDAP/SAMR/loot/bloodhound/credential sources into user_intel.json."""
    users_data = _load_json(ws_path / "users.json")
    inventory = _load_json(ws_path / "auth_inventory.json")
    manifest = _load_json(ws_path / "loot_manifest.json")
    cred_data = _load_json(ws_path / "credentials.json")
    user_enum = _load_json(ws_path / "user_enum.json") or {}
    enum_sources = list(user_enum.get("sources_used") or [])

    by_user: dict[str, MatchedUser] = {}

    for item in users_data.get("users") or []:
        username = str(item.get("username", ""))
        if not username:
            continue
        key = username.lower()
        by_user[key] = MatchedUser(
            username=username,
            sources=sorted(set(item.get("sources") or [])),
            in_domain=True,
            description=item.get("description"),
        )
        if enum_sources:
            _merge_sources(by_user[key], *enum_sources)

    for item in inventory.get("users") or []:
        username = str(item.get("username", ""))
        if not username:
            continue
        key = username.lower()
        if key not in by_user:
            by_user[key] = MatchedUser(username=username, in_domain=True)
        entry = by_user[key]
        _merge_sources(entry, "ldap_auth")
        entry.in_domain = True
        if item.get("description"):
            entry.description = str(item.get("description"))

    loot_only: list[str] = []
    for item in manifest.get("parsed_credentials") or []:
        username = str(item.get("username", ""))
        password = str(item.get("password", ""))
        if not username:
            continue
        key = username.lower()
        if key not in by_user:
            by_user[key] = MatchedUser(username=username, sources=["share_loot"], in_domain=False)
            loot_only.append(username)
        else:
            entry = by_user[key]
            _merge_sources(entry, "share_loot")
        by_user[key].loot_password = password or by_user[key].loot_password

    bh_users_path = ws_path / "bloodhound" / "users.json"
    if bh_users_path.is_file():
        bh = _load_json(bh_users_path)
        for item in bh.get("data") or []:
            props = item.get("Properties") or {}
            raw_name = str(props.get("name") or props.get("samaccountname") or "")
            if not raw_name:
                continue
            username = _normalize_bh_username(raw_name)
            if not username:
                continue
            key = username
            if key not in by_user:
                by_user[key] = MatchedUser(
                    username=username,
                    sources=["bloodhound"],
                    in_domain=True,
                )
            else:
                _merge_sources(by_user[key], "bloodhound")

    credentials = cred_data.get("credentials") or []
    for entry in by_user.values():
        entry.cred_status = _best_cred_status(credentials, entry.username)

    matched = sorted(by_user.values(), key=lambda u: u.username.lower())
    payload = {
        "user_count": len(matched),
        "loot_only_usernames": loot_only,
        "users": [u.to_dict() for u in matched],
    }
    out = ws_path / "user_intel.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def refresh_workspace_intel(ws_path: Path | str, *, users_store: UsersStore | None = None) -> None:
    ws_path = Path(ws_path)
    """Loot → users.json merge, then user_intel + password_candidates."""
    manifest = _load_json(ws_path / "loot_manifest.json")
    if users_store is not None and manifest:
        sync_loot_users(users_store, manifest)
    from admapper.creds.password_candidates import build_password_candidates_file

    build_user_intel(ws_path)
    build_password_candidates_file(ws_path)
