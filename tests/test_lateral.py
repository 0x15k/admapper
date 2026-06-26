from unittest.mock import MagicMock, patch

from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.exploit.lateral import check_winrm_password_access


def _session(tmp_path) -> Session:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.set_hosts("192.168.10.182")
    return session


def test_check_winrm_password_access_denied(tmp_path) -> None:
    session = _session(tmp_path)
    proc = MagicMock(returncode=1, stdout="STATUS_LOGON_FAILURE", stderr="")
    with (
        patch("admapper.exploit.lateral.resolve_nxc", return_value="/usr/bin/nxc"),
        patch("admapper.exploit.lateral.run_command", return_value=proc),
    ):
        check = check_winrm_password_access(
            session,
            username="target.user",
            password="KnownPassword123!",
            host="192.168.10.182",
        )
    assert check is not None
    assert check.success is False


def test_check_winrm_password_access_confirmed(tmp_path) -> None:
    session = _session(tmp_path)
    proc = MagicMock(returncode=0, stdout="(Pwn3d!) target.example\\admin", stderr="")
    with (
        patch("admapper.exploit.lateral.resolve_nxc", return_value="/usr/bin/nxc"),
        patch("admapper.exploit.lateral.run_command", return_value=proc),
    ):
        check = check_winrm_password_access(
            session,
            username="target.admin",
            password="Secret123!",
            host="192.168.10.182",
        )
    assert check is not None
    assert check.success is True
