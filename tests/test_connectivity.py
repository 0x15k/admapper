from pathlib import Path
from unittest.mock import patch

import pytest

from admapper.core.connectivity import (
    TargetUnreachableError,
    format_unreachable_message,
    require_target_reachable,
)
from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager


def _session(tmp_path: Path, hosts: str = "10.129.20.182") -> Session:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.workspace.hosts = hosts
    session.persist_workspace()
    return session


def test_format_unreachable_no_route() -> None:
    msg = format_unreachable_message(
        TargetUnreachableError("10.129.20.182", "[Errno 113] No route to host")
    )
    assert "no alcanzable" in msg
    assert "apagada" in msg or "VPN" in msg


def test_require_target_reachable_raises(tmp_path: Path) -> None:
    session = _session(tmp_path)
    with patch(
        "admapper.core.connectivity.probe_host_reachable",
        return_value=(False, "[Errno 113] No route to host"),
    ):
        with pytest.raises(TargetUnreachableError):
            require_target_reachable(session)


def test_check_target_reachable_open_port() -> None:
    from admapper.core.reachability import check_target_reachable

    with patch("admapper.core.reachability.socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = lambda s, *a: None
        ok, detail = check_target_reachable("10.0.0.1")

    assert ok is True
    assert "tcp/445" in detail
    mock_conn.assert_called_once_with(("10.0.0.1", 445), timeout=3.0)


def test_check_target_reachable_no_route() -> None:
    from admapper.core.reachability import check_target_reachable

    with patch(
        "admapper.core.reachability.socket.create_connection",
        side_effect=OSError("[Errno 113] No route to host"),
    ):
        ok, detail = check_target_reachable("10.129.20.182")

    assert ok is False
    assert "No route to host" in detail
