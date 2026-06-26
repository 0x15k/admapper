from __future__ import annotations

from pathlib import Path

import pytest

from admapper.core.dashboard_mode import (
    DASHBOARD_MODE_ENV,
    effective_sync_clock,
    effective_sync_hosts,
    enable_dashboard_mode,
    dashboard_subprocess_env,
    is_dashboard_mode,
)
from admapper.core.operator_setup import build_operator_setup


@pytest.fixture(autouse=True)
def _clear_dashboard_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DASHBOARD_MODE_ENV, raising=False)


def test_dashboard_mode_env_disables_sync() -> None:
    assert effective_sync_clock(True) is True
    assert effective_sync_hosts(True) is True
    enable_dashboard_mode()
    assert is_dashboard_mode()
    assert effective_sync_clock(True) is False
    assert effective_sync_hosts(True) is False


def test_dashboard_subprocess_env_sets_flag() -> None:
    env = dashboard_subprocess_env()
    assert env.get(DASHBOARD_MODE_ENV) == "1"


def test_operator_setup_hints(tmp_path: Path) -> None:
    setup = build_operator_setup(
        tmp_path,
        dc_ip="10.0.0.1",
        dc_host="dc.target.example",
    )
    assert setup["hosts_entry"] == "10.0.0.1  dc.target.example"
    assert setup["sync_dc_cmd"] == "admapper sync-dc -H 10.0.0.1"
    assert "sudo sntp" in (setup["sync_clock_cmd"] or "")
