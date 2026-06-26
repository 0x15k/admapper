from __future__ import annotations

import json
from pathlib import Path

from admapper.models.spray import SprayAttempt
from admapper.support.workspace import WorkspaceManager


class SprayHistoryStore:
    """Track sprayed passwords to avoid repeating attempts."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    @property
    def _path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "spray_history.json"

    def list(self) -> list[SprayAttempt]:
        if not self._path.is_file():
            return []
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return [SprayAttempt.from_dict(item) for item in data.get("attempts", [])]

    def save_all(self, attempts: list[SprayAttempt]) -> Path:
        workspace_dir = self._workspace.path_for(self._workspace_name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        payload = {"attempts": [a.to_dict() for a in attempts]}
        self._path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self._path

    def add(self, attempt: SprayAttempt) -> SprayAttempt:
        attempts = self.list()
        attempts.append(attempt)
        self.save_all(attempts)
        return attempt

    def password_already_sprayed(self, password: str) -> bool:
        needle = password.casefold()
        return any(a.password.casefold() == needle for a in self.list())
