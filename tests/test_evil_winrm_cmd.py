from unittest.mock import MagicMock, patch

from admapper.creds.common import format_admapper_winrm_pth, format_evil_winrm_pth
from admapper.winrm.shell_cli import run_winrm_shell


def test_evil_winrm_pth_no_d_flag() -> None:
    host, cmd = format_evil_winrm_pth(
        account="msa_target$",
        nthash="a" * 32,
        domain="target.example",
        ws_path=None,
        fallback_ip="10.0.0.1",
    )
    assert host == "dc01.target.example"
    assert "-d " not in cmd
    assert "target.example\\msa_target$" in cmd
    assert cmd.startswith("evil-winrm -i dc01.target.example")


def test_admapper_winrm_pth_no_dc_ip_flag() -> None:
    _, cmd = format_admapper_winrm_pth(
        account="msa_target$",
        nthash="b" * 32,
        domain="target.example",
        ws_path=None,
        fallback_ip="10.0.0.1",
    )
    assert "--dc-ip" not in cmd
    assert "dc01.target.example" in cmd
    assert "admapper winrm -H" in cmd



def test_run_winrm_shell_pth_accepts_fqdn_without_dc_ip() -> None:
    mock_result = MagicMock(stdout="corp\\msa_target$\n", stderr="", returncode=0, shell="cmd")
    with patch("admapper.winrm.shell_cli.WinRMClient") as mock_cls:
        mock_cls.return_value.execute.return_value = mock_result
        run_winrm_shell(
            host="msa_target.target.example",
            domain="target.example",
            username="msa_target$",
            password=None,
            nthash="c" * 32,
            dc_ip=None,
            dc_fqdn="msa_target.target.example",
            command="whoami",
            ccache=None,
            clock_skew=None,
            sync_clock=False,
        )
    mock_cls.assert_called_once()
    assert mock_cls.call_args.kwargs["ticket_method"] == "nthash"
