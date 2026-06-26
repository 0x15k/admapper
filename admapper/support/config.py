from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from admapper.models.workspace import OperationMode
from admapper.support.paths import global_config_path
from admapper.support.platform import ensure_user_dirs


@dataclass
class GlobalConfig:
    """Operator preferences persisted under ~/.admapper/config.json."""

    default_mode: OperationMode = OperationMode.SEMI
    workspaces_root: str | None = None
    active_workspace: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_mode": self.default_mode.value,
            "workspaces_root": self.workspaces_root,
            "active_workspace": self.active_workspace,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GlobalConfig:
        mode_raw = str(data.get("default_mode", OperationMode.SEMI.value))
        try:
            mode = OperationMode(mode_raw)
        except ValueError:
            mode = OperationMode.SEMI
        return cls(
            default_mode=mode,
            workspaces_root=data.get("workspaces_root"),
            active_workspace=data.get("active_workspace"),
        )


def load_config(path: Path | None = None) -> GlobalConfig:
    cfg_path = path or global_config_path()
    if not cfg_path.is_file():
        return GlobalConfig()
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    return GlobalConfig.from_dict(data)


def save_config(config: GlobalConfig, path: Path | None = None) -> Path:
    cfg_path = path or global_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        json.dumps(config.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return cfg_path


def ensure_config_dir() -> Path:
    dirs = ensure_user_dirs()
    return dirs["config"]
