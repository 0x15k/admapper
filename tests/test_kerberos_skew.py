from pathlib import Path
from unittest.mock import MagicMock, patch

from admapper.creds.kerberos_skew import (
    check_kerberos_with_skew,
    ensure_workspace_skew,
    load_workspace_clock_skew,
    save_workspace_clock_skew,
    seconds_to_faketime_offset,
)
from admapper.core.platform import get_clock_skew, set_clock_skew


def test_seconds_to_faketime_offset_hours() -> None:
    assert seconds_to_faketime_offset(25200) == "+7h"
    assert seconds_to_faketime_offset(-25200) == "-7h"


def test_workspace_clock_skew_roundtrip(tmp_path: Path) -> None:
    save_workspace_clock_skew(tmp_path, "+7h", dc_ip="10.0.0.1", stepped_seconds=25200.0)
    assert load_workspace_clock_skew(tmp_path) == "+7h"
    data = (tmp_path / "kerberos_clock.json").read_text(encoding="utf-8")
    assert "10.0.0.1" in data
    assert "25200" in data


def test_ensure_workspace_skew_loads_cache(tmp_path: Path) -> None:
    save_workspace_clock_skew(tmp_path, "+7h")
    set_clock_skew(None)
    with patch("admapper.creds.kerberos_skew.resolve_faketime", return_value="/usr/bin/faketime"):
        applied = ensure_workspace_skew(tmp_path)
    assert applied == "+7h"
    assert get_clock_skew() == "+7h"
    set_clock_skew(None)


def test_check_kerberos_with_skew_uses_workspace_cache(tmp_path: Path) -> None:
    save_workspace_clock_skew(tmp_path, "+7h")
    set_clock_skew(None)
    with patch(
        "admapper.creds.kerberos_skew._kerberos_subprocess",
        side_effect=lambda *a, **kw: kw.get("clock_skew") == "+7h",
    ) as mock_krb:
        ok, applied = check_kerberos_with_skew(
            "corp.local",
            "svc_sql",
            "secret",
            dc_ip="192.168.10.182",
            ws_path=tmp_path,
            skip_system_time=True,
        )
    assert ok is True
    assert applied == "+7h"
    assert get_clock_skew() == "+7h"
    assert mock_krb.call_count >= 1


def test_check_kerberos_with_skew_probes_after_system_failure(tmp_path: Path) -> None:
    set_clock_skew(None)
    with (
        patch("admapper.creds.kerberos_skew.resolve_faketime", return_value="/usr/bin/faketime"),
        patch(
            "admapper.creds.kerberos_skew._kerberos_subprocess",
            side_effect=lambda *a, **kw: kw.get("clock_skew") == "+7h",
        ) as mock_krb,
    ):
        ok, applied = check_kerberos_with_skew(
            "corp.local",
            "svc_sql",
            "secret",
            dc_ip="192.168.10.182",
            ws_path=tmp_path,
        )
    assert ok is True
    assert applied == "+7h"
    assert any(call.kwargs.get("clock_skew") is None for call in mock_krb.call_args_list)
    assert any(call.kwargs.get("clock_skew") == "+7h" for call in mock_krb.call_args_list)


def test_query_dc_time_ldap() -> None:
    from datetime import datetime, timezone
    from admapper.creds.time_sync import query_dc_time_ldap

    mock_info = MagicMock()
    mock_info.other = {"currentTime": "20260625233804.0Z"}
    mock_server = MagicMock()
    mock_server.info = mock_info

    with (
        patch("admapper.creds.time_sync.Server", return_value=mock_server),
        patch("admapper.creds.time_sync.Connection") as mock_conn,
    ):
        dc_time = query_dc_time_ldap("192.168.10.130")

    assert dc_time is not None
    assert dc_time == datetime(2026, 6, 25, 23, 38, 4, tzinfo=timezone.utc)


def test_calculate_ldap_clock_skew() -> None:
    from datetime import datetime, timezone
    from admapper.creds.time_sync import calculate_ldap_clock_skew

    dc_time = datetime(2026, 6, 25, 23, 38, 4, tzinfo=timezone.utc)
    local_time = datetime(2026, 6, 25, 16, 38, 4, tzinfo=timezone.utc)

    with (
        patch("admapper.creds.time_sync.query_dc_time_ldap", return_value=dc_time),
        patch("admapper.creds.time_sync.datetime") as mock_dt,
    ):
        mock_dt.now.return_value = local_time
        skew = calculate_ldap_clock_skew("192.168.10.130")

    # +7 hours = 25200 seconds
    assert skew == 25200.0


def test_ensure_dc_clock_with_ldap_skew(tmp_path: Path) -> None:
    from admapper.creds.time_sync import ensure_dc_clock, reset_dc_clock_state
    reset_dc_clock_state()
    set_clock_skew(None)

    with (
        patch("admapper.creds.time_sync.calculate_ldap_clock_skew", return_value=25200.0),
        patch("admapper.creds.time_sync.sync_time_to_dc", return_value=(False, "sync failed")),
    ):
        # Even if sync fails, the LDAP derived clock skew will set and return True
        res = ensure_dc_clock("192.168.10.130", enabled=True, ws_path=tmp_path)

    assert res is True
    assert get_clock_skew() == "+7h"
    set_clock_skew(None)
