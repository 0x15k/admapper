from __future__ import annotations

import json
from pathlib import Path

from admapper.core.workspace import WorkspaceManager
from admapper.models.finding import Finding


class FindingsStore:
    """JSON-backed findings list for the active workspace."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    @property
    def _path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "findings.json"

    def list(self) -> list[Finding]:
        if not self._path.is_file():
            return []
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return [Finding.from_dict(item) for item in data.get("findings", [])]

    def save_all(self, findings: list[Finding]) -> Path:
        workspace_dir = self._workspace.path_for(self._workspace_name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        payload = {"findings": [f.to_dict() for f in findings]}
        self._path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self._path

    def merge(self, new_findings: list[Finding]) -> list[Finding]:
        existing = {f.key: f for f in self.list()}
        for finding in new_findings:
            existing[finding.key] = finding
        merged = list(existing.values())
        self.save_all(merged)
        return merged
