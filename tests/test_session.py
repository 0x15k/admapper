from pathlib import Path

from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.workspace import OperationMode


def test_session_select_workspace_persists_active(tmp_path: Path) -> None:
    session = Session(
        config=GlobalConfig(),
        workspaces=WorkspaceManager(tmp_path / "workspaces"),
    )
    state = session.select_workspace("pentest-01")
    assert state.name == "pentest-01"
    assert session.config.active_workspace == "pentest-01"

    reloaded = Session.bootstrap(workspaces_root=tmp_path / "workspaces")
    assert reloaded.workspace is not None
    assert reloaded.workspace.name == "pentest-01"


def test_session_set_domain_and_mode(tmp_path: Path) -> None:
    session = Session.bootstrap(workspaces_root=tmp_path / "ws")
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.set_mode(OperationMode.MANUAL)

    reloaded = Session.bootstrap(workspaces_root=tmp_path / "ws")
    assert reloaded.workspace is not None
    assert reloaded.workspace.domain == "target.example"
    assert reloaded.workspace.mode == OperationMode.MANUAL
