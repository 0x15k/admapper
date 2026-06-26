from __future__ import annotations

import os
from pathlib import Path

from admapper.support.platform import user_config_dir

WORKSPACES_ENV_VAR = "ADMAPPER_WORKSPACES"

_cli_workspaces_root: Path | None = None


def global_config_dir() -> Path:
    return user_config_dir()


def global_config_path() -> Path:
    return global_config_dir() / "config.json"


def set_cli_workspaces_root(path: Path | None) -> None:
    """Per-invocation override from ``admapper --workspaces-root``."""
    global _cli_workspaces_root
    _cli_workspaces_root = path.expanduser().resolve() if path else None


def get_cli_workspaces_root() -> Path | None:
    return _cli_workspaces_root


def default_user_workspaces_root() -> Path:
    """Operator home — default for engagements (never inside the git clone)."""
    root = user_config_dir() / "workspaces"
    root.mkdir(parents=True, exist_ok=True)
    return root


def legacy_repo_workspaces() -> Path | None:
    """Dev path: ``<repo>/workspaces`` when present."""
    repo = find_repo_root()
    if repo is None:
        return None
    ws = repo / "workspaces"
    return ws if ws.is_dir() else None


def resolve_workspaces_root(
    *,
    cli_override: Path | str | None = None,
    config_root: Path | str | None = None,
) -> Path:
    """
    Resolve where engagement data is stored.

    Priority: explicit arg → CLI global flag → env → config → ~/.admapper/workspaces
    """
    if cli_override:
        root = Path(cli_override).expanduser().resolve()
    elif get_cli_workspaces_root() is not None:
        root = get_cli_workspaces_root()  # type: ignore[assignment]
    elif os.environ.get(WORKSPACES_ENV_VAR):
        root = Path(os.environ[WORKSPACES_ENV_VAR]).expanduser().resolve()
    elif config_root:
        root = Path(config_root).expanduser().resolve()
    else:
        root = default_user_workspaces_root()
    root.mkdir(parents=True, exist_ok=True)
    return root


def find_repo_root(start: Path | None = None) -> Path | None:
    """Walk up from *start* (or cwd) to locate the ADMapper repo root."""
    cur = (start or Path.cwd()).resolve()
    for _ in range(12):
        if (cur / "pyproject.toml").is_file() and (cur / "admapper" / "__init__.py").is_file():
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return None


def is_package_source_dir(path: Path) -> bool:
    """True when *path* is the inner ``admapper/`` package (cli/, core/), not repo root."""
    p = path.resolve()
    return (
        (p / "cli").is_dir()
        and (p / "core").is_dir()
        and (p / "__init__.py").is_file()
        and not (p / "pyproject.toml").is_file()
    )


def default_workspaces_root() -> Path:
    """Backward-compatible alias used by WorkspaceManager when no explicit root is passed."""
    return resolve_workspaces_root()
