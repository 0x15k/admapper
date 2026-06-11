from unittest.mock import MagicMock, patch

from admapper.core.platform import get_clock_skew, set_clock_skew
from admapper.creds.kerberos_skew import load_workspace_clock_skew
from admapper.creds.time_sync import (
    _resolve_linux_ntp_binary,
    ensure_dc_clock,
    parse_ntp_step_seconds,
    reset_dc_clock_state,
    suggest_time_sync,
    sync_time_to_dc,
    vm_time_sync_warning,
)


def test_ensure_dc_clock_runs_ntpdate() -> None:
    reset_dc_clock_state()
    set_clock_skew(None)
    with patch(
        "admapper.creds.time_sync.sync_time_to_dc",
        return_value=(True, "ntpdate synced to 10.0.0.1"),
    ):
        assert ensure_dc_clock("10.0.0.1") is True


def test_ensure_dc_clock_disabled() -> None:
    with patch("admapper.creds.time_sync.sync_time_to_dc") as mock_sync:
        assert ensure_dc_clock("10.0.0.1", enabled=False) is False
        mock_sync.assert_not_called()


def test_resolve_linux_ntp_binary_prefers_ntpdate() -> None:
    with patch("admapper.creds.time_sync.shutil.which") as mock_which:
        mock_which.side_effect = lambda name: (
            "/usr/bin/ntpdate" if name == "ntpdate" else "/usr/bin/ntpsec-ntpdate"
        )
        assert _resolve_linux_ntp_binary() == "ntpdate"
        mock_which.assert_called_once_with("ntpdate")


def test_resolve_linux_ntp_binary_falls_back_to_ntpsec_ntpdate() -> None:
    with patch("admapper.creds.time_sync.shutil.which") as mock_which:
        mock_which.side_effect = lambda name: (
            "/usr/bin/ntpsec-ntpdate" if name == "ntpsec-ntpdate" else None
        )
        assert _resolve_linux_ntp_binary() == "ntpsec-ntpdate"
        assert mock_which.call_args_list == [
            (("ntpdate",),),
            (("ntpsec-ntpdate",),),
        ]


def test_resolve_linux_ntp_binary_returns_none_when_missing() -> None:
    with patch("admapper.creds.time_sync.shutil.which", return_value=None):
        assert _resolve_linux_ntp_binary() is None


def test_sync_time_to_dc_uses_ntpsec_ntpdate_on_linux() -> None:
    with (
        patch("admapper.creds.time_sync.is_linux", return_value=True),
        patch("admapper.creds.time_sync._resolve_linux_ntp_binary", return_value="ntpsec-ntpdate"),
        patch("admapper.creds.time_sync._sntp_available", return_value=False),
        patch("admapper.creds.time_sync.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout="step time server", stderr="")
        ok, detail = sync_time_to_dc("10.129.20.182")
        assert ok is True
        assert "ntpsec-ntpdate synced" in detail
        mock_run.assert_called_once()
        assert mock_run.call_args.args[0] == ["sudo", "ntpsec-ntpdate", "10.129.20.182"]


def test_sync_time_to_dc_linux_failure_message_mentions_ntpsec_ntpdate() -> None:
    with (
        patch("admapper.creds.time_sync.is_linux", return_value=True),
        patch("admapper.creds.time_sync.is_macos", return_value=False),
        patch("admapper.creds.time_sync._resolve_linux_ntp_binary", return_value=None),
        patch("admapper.creds.time_sync._sntp_available", return_value=False),
    ):
        ok, detail = sync_time_to_dc("10.129.20.182")
        assert ok is False
        assert "ntpsec-ntpdate" in detail


def test_suggest_time_sync_uses_ntpsec_ntpdate_on_linux() -> None:
    with (
        patch("admapper.creds.time_sync.is_linux", return_value=True),
        patch("admapper.creds.time_sync.is_macos", return_value=False),
        patch("admapper.creds.time_sync._resolve_linux_ntp_binary", return_value="ntpsec-ntpdate"),
    ):
        assert suggest_time_sync("10.129.20.182") == "sudo ntpsec-ntpdate 10.129.20.182"


def test_parse_ntp_step_seconds() -> None:
    output = "ntpdate synced to 10.0.0.1: 10 Jun 12:00:00 ntpdate[1]: time stepped by 25200.123456 sec"
    assert parse_ntp_step_seconds(output) == 25200.123456


def test_vm_time_sync_warning() -> None:
    msg = vm_time_sync_warning(25200)
    assert "25200" in msg
    assert "VM guest time sync" in msg


def test_ensure_dc_clock_large_step_sets_skew(tmp_path) -> None:
    reset_dc_clock_state()
    set_clock_skew(None)
    detail = (
        "ntpsec-ntpdate synced to 10.129.20.182: "
        "time stepped by 25200.000000 sec, adjustment +25200.000000 sec"
    )
    with patch("admapper.creds.time_sync.sync_time_to_dc", return_value=(True, detail)):
        assert ensure_dc_clock("10.129.20.182", ws_path=tmp_path) is True
    assert get_clock_skew() == "+7h"
    assert load_workspace_clock_skew(tmp_path) == "+7h"
    set_clock_skew(None)
    reset_dc_clock_state()


def test_ensure_dc_clock_skips_ntpdate_when_explicit_skew() -> None:
    reset_dc_clock_state()
    set_clock_skew("+7h")
    with patch("admapper.creds.time_sync.sync_time_to_dc") as mock_sync:
        ensure_dc_clock("10.129.20.182")
        ensure_dc_clock("10.129.20.182")
    mock_sync.assert_not_called()


def test_ensure_dc_clock_skips_repeat_sync_when_unstable(tmp_path) -> None:
    reset_dc_clock_state()
    set_clock_skew(None)
    detail = "ntpsec-ntpdate synced: time stepped by 25200.000000 sec"
    with patch("admapper.creds.time_sync.sync_time_to_dc", return_value=(True, detail)) as mock_sync:
        ensure_dc_clock("10.129.20.182", ws_path=tmp_path)
        ensure_dc_clock("10.129.20.182", ws_path=tmp_path)
    assert mock_sync.call_count == 1
