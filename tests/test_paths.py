import os
from pathlib import Path

from admapper.core.paths import (
    WORKSPACES_ENV_VAR,
    default_user_workspaces_root,
    resolve_workspaces_root,
    set_cli_workspaces_root,
)


def test_resolve_workspaces_root_defaults_to_user_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("admapper.core.paths.user_config_dir", lambda: tmp_path / ".admapper")
    set_cli_workspaces_root(None)
    monkeypatch.delenv(WORKSPACES_ENV_VAR, raising=False)
    root = resolve_workspaces_root()
    assert root == tmp_path / ".admapper" / "workspaces"


def test_resolve_workspaces_root_cli_flag(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "engagements"
    set_cli_workspaces_root(target)
    monkeypatch.delenv(WORKSPACES_ENV_VAR, raising=False)
    assert resolve_workspaces_root() == target.resolve()


def test_resolve_workspaces_root_env(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "from-env"
    set_cli_workspaces_root(None)
    monkeypatch.setenv(WORKSPACES_ENV_VAR, str(target))
    assert resolve_workspaces_root() == target.resolve()


def test_resolve_workspaces_root_explicit_override(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "explicit"
    set_cli_workspaces_root(None)
    monkeypatch.delenv(WORKSPACES_ENV_VAR, raising=False)
    assert resolve_workspaces_root(cli_override=target) == target.resolve()
