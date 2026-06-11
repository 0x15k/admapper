from __future__ import annotations

import json
from pathlib import Path

from admapper.core.workspace import WorkspaceManager
from admapper.models.user import UserRecord, apply_uac_flags


class UsersStore:
    """JSON-backed unified user inventory."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    @property
    def _path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "users.json"

    def list(self) -> list[UserRecord]:
        if not self._path.is_file():
            return []
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return [UserRecord.from_dict(item) for item in data.get("users", [])]

    def save_all(self, users: list[UserRecord]) -> Path:
        workspace_dir = self._workspace.path_for(self._workspace_name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        payload = {"users": [u.to_dict() for u in users]}
        self._path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self._path

    def merge(self, new_users: list[UserRecord]) -> list[UserRecord]:
        by_name: dict[str, UserRecord] = {u.username.lower(): u for u in self.list()}
        for incoming in new_users:
            key = incoming.username.lower()
            if key not in by_name:
                by_name[key] = apply_uac_flags(incoming)
                continue
            existing = by_name[key]
            merged_sources = sorted(set(existing.sources) | set(incoming.sources))
            merged_spns = sorted(set(existing.spns) | set(incoming.spns))
            merged = UserRecord(
                username=existing.username,
                sources=merged_sources,
                rid=incoming.rid or existing.rid,
                description=incoming.description or existing.description,
                dn=incoming.dn or existing.dn,
                uac=incoming.uac if incoming.uac is not None else existing.uac,
                spns=merged_spns,
                asrep_roastable=existing.asrep_roastable or incoming.asrep_roastable,
                kerberoastable=existing.kerberoastable or incoming.kerberoastable,
                password_not_required=(
                    existing.password_not_required or incoming.password_not_required
                ),
                enabled=existing.enabled and incoming.enabled,
                bad_pwd_count=(
                    incoming.bad_pwd_count
                    if incoming.bad_pwd_count is not None
                    else existing.bad_pwd_count
                ),
                lockout_time=(
                    incoming.lockout_time
                    if incoming.lockout_time is not None
                    else existing.lockout_time
                ),
            )
            by_name[key] = apply_uac_flags(merged)
        merged_list = sorted(by_name.values(), key=lambda u: u.username.lower())
        self.save_all(merged_list)
        return merged_list
