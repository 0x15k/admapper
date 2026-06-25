from pathlib import Path

from admapper.cli.commands import dispatch
from admapper.core.session import Session


def test_dispatch_exit_persists_workspace(tmp_path: Path) -> None:
    session = Session.bootstrap(workspaces_root=tmp_path / "ws")
    dispatch(session, "set workspace demo")
    assert session.workspace is not None
    assert dispatch(session, "exit") is False
    assert (tmp_path / "ws" / "demo" / "state.json").is_file()


def test_dispatch_unknown_command(tmp_path: Path) -> None:
    session = Session.bootstrap(workspaces_root=tmp_path / "ws")
    assert dispatch(session, "not-a-command") is True


def test_cli_web_no_args_exits_with_error() -> None:
    from typer.testing import CliRunner
    from admapper.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["web"])
    assert result.exit_code != 0
    assert "specify a target" in result.stdout


def test_cli_dashboard_no_args_exits_with_error() -> None:
    from typer.testing import CliRunner
    from admapper.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["dashboard"])
    assert result.exit_code != 0
    assert "specify a target" in result.stdout
