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


def test_cli_web_with_host_runs_unauth_discovery(tmp_path: Path) -> None:
    from unittest.mock import patch
    from typer.testing import CliRunner
    from admapper.cli.main import app

    runner = CliRunner()
    with (
        patch("admapper.recon.ports.scan_host", return_value=[389]) as mock_scan,
        patch("admapper.recon.unauth.run_unauth_scan") as mock_unauth,
        patch("admapper.core.discovery.ensure_domain", return_value="corp.local") as mock_ensure,
        patch("admapper.cli.scan.sync_hosts_from_session") as mock_sync,
        patch("admapper.graph.dashboard_server.run_dashboard_server") as mock_run_server,
    ):
        result = runner.invoke(app, [
            "--workspaces-root", str(tmp_path / "ws1"),
            "web", "-H", "10.129.35.99", "--no-open"
        ])
        assert result.exit_code == 0
        mock_scan.assert_called_once()
        mock_unauth.assert_called_once()
        mock_ensure.assert_called_once()
        mock_sync.assert_called_once()
        mock_run_server.assert_called_once()


def test_cli_dashboard_with_host_runs_unauth_discovery(tmp_path: Path) -> None:
    from unittest.mock import patch
    from typer.testing import CliRunner
    from admapper.cli.main import app

    runner = CliRunner()
    with (
        patch("admapper.recon.ports.scan_host", return_value=[389]) as mock_scan,
        patch("admapper.recon.unauth.run_unauth_scan") as mock_unauth,
        patch("admapper.core.discovery.ensure_domain", return_value="corp.local") as mock_ensure,
        patch("admapper.cli.scan.sync_hosts_from_session") as mock_sync,
        patch("admapper.graph.dashboard_server.run_dashboard_server") as mock_run_server,
        patch("admapper.graph.ops_ui.write_ops_html") as mock_write_html,
    ):
        result = runner.invoke(app, [
            "--workspaces-root", str(tmp_path / "ws2"),
            "dashboard", "-H", "10.129.35.99", "--no-open"
        ])
        assert result.exit_code == 0
        mock_scan.assert_called_once()
        mock_unauth.assert_called_once()
        mock_ensure.assert_called_once()
        mock_sync.assert_called_once()
        mock_run_server.assert_called_once()
        mock_write_html.assert_called_once()


def test_cli_web_unreachable_exits_with_error(tmp_path: Path) -> None:
    from unittest.mock import patch
    from typer.testing import CliRunner
    from admapper.cli.main import app

    runner = CliRunner()
    with patch("admapper.recon.ports.scan_host", return_value=[]) as mock_scan:
        result = runner.invoke(app, [
            "--workspaces-root", str(tmp_path / "ws3"),
            "web", "-H", "10.129.35.99", "--no-open"
        ])
        assert result.exit_code != 0
        assert "unreachable or AD ports" in result.stdout
        mock_scan.assert_called_once()


def test_cli_dashboard_unreachable_exits_with_error(tmp_path: Path) -> None:
    from unittest.mock import patch
    from typer.testing import CliRunner
    from admapper.cli.main import app

    runner = CliRunner()
    with patch("admapper.recon.ports.scan_host", return_value=[]) as mock_scan:
        result = runner.invoke(app, [
            "--workspaces-root", str(tmp_path / "ws4"),
            "dashboard", "-H", "10.129.35.99", "--no-open"
        ])
        assert result.exit_code != 0
        assert "unreachable or AD ports" in result.stdout
        mock_scan.assert_called_once()
