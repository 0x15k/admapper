from __future__ import annotations

import json
import re
from pathlib import Path

from admapper.models.workspace import OperationMode, WorkspaceState
from admapper.support.paths import default_workspaces_root

_WORKSPACE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


def _validate_workspace_name(name: str) -> str:
    cleaned = name.strip()
    # Bracketed-paste artifact: iTerm/Terminal sometimes appends '~'
    if cleaned.endswith("~"):
        candidate = cleaned[:-1].strip()
        if _WORKSPACE_NAME_RE.fullmatch(candidate):
            cleaned = candidate
    if not _WORKSPACE_NAME_RE.fullmatch(cleaned):
        hint = ""
        if name.strip().endswith("~"):
            hint = (
                f" — did you mean '{name.strip().rstrip('~')}'? (remove bracketed-paste trailing ~)"
            )
        raise ValueError(
            "workspace name must be 1-64 chars: letters, digits, '.', '_' or '-'" + hint
        )
    return cleaned


class WorkspaceManager:
    """Create, load and persist workspace state on disk."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or default_workspaces_root()).resolve()

    def path_for(self, name: str) -> Path:
        safe_name = _validate_workspace_name(name)
        primary = self.root / safe_name
        if (primary / "state.json").is_file():
            return primary

        from admapper.support.platform import user_config_dir

        global_root = user_config_dir() / "workspaces"
        global_path = global_root / safe_name
        if (global_path / "state.json").is_file():
            return global_path

        return primary

    def list_workspaces(self) -> list[str]:
        found = set()
        if self.root.is_dir():
            for p in self.root.iterdir():
                if p.is_dir() and (p / "state.json").is_file():
                    found.add(p.name)

        from admapper.support.platform import user_config_dir

        global_root = (user_config_dir() / "workspaces").resolve()
        if global_root.is_dir() and global_root != self.root.resolve():
            for p in global_root.iterdir():
                if p.is_dir() and (p / "state.json").is_file():
                    found.add(p.name)
        return sorted(found)

    def exists(self, name: str) -> bool:
        return (self.path_for(name) / "state.json").is_file()

    def create(self, name: str, *, mode: OperationMode | None = None) -> WorkspaceState:
        workspace_dir = self.path_for(name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        state = WorkspaceState(name=_validate_workspace_name(name), mode=mode or OperationMode.SEMI)
        self.save(state)
        return state

    def load(self, name: str) -> WorkspaceState:
        state_path = self.path_for(name) / "state.json"
        if not state_path.is_file():
            from admapper.support.paths import (
                find_repo_root,
                is_package_source_dir,
                legacy_repo_workspaces,
            )

            hints: list[str] = []
            if is_package_source_dir(Path.cwd()):
                repo = find_repo_root()
                if repo:
                    hints.append(f"cd {repo}")
            legacy = legacy_repo_workspaces()
            if legacy and legacy != self.root and (legacy / name / "state.json").is_file():
                hints.append(f"admapper -O {legacy} ... or set workspaces {legacy}")
            suffix = f" — {'; '.join(hints)}" if hints else ""
            raise FileNotFoundError(
                f"workspace not found: {name} (searched in {self.root}){suffix}"
            )
        data = json.loads(state_path.read_text(encoding="utf-8"))
        return WorkspaceState.from_dict(data)

    def save(self, state: WorkspaceState) -> Path:
        workspace_dir = self.path_for(state.name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        state_path = workspace_dir / "state.json"
        state_path.write_text(
            json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return state_path

    def get_or_create(self, name: str, *, mode: OperationMode | None = None) -> WorkspaceState:
        if self.exists(name):
            return self.load(name)
        return self.create(name, mode=mode)
