from pathlib import Path

import pytest

from admapper.core.workspace import WorkspaceManager
from admapper.models.workspace import OperationMode


def test_create_and_load_workspace(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path)
    created = manager.create("lab01", mode=OperationMode.AUTO)
    assert created.name == "lab01"
    assert created.mode == OperationMode.AUTO

    loaded = manager.load("lab01")
    assert loaded.name == "lab01"
    assert loaded.mode == OperationMode.AUTO


def test_workspace_persists_domain_and_hosts(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path)
    state = manager.create("engagement-a")
    state.domain = "target.example"
    state.hosts = "192.168.56.0/24"
    manager.save(state)

    loaded = manager.load("engagement-a")
    assert loaded.domain == "target.example"
    assert loaded.hosts == "192.168.56.0/24"


def test_invalid_workspace_name(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path)
    with pytest.raises(ValueError):
        manager.create("../escape")
