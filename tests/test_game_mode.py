from __future__ import annotations

from pathlib import Path

import pytest

from admapper.core.game_mode import (
    GAME_MODE_ENV,
    effective_sync_clock,
    effective_sync_hosts,
    enable_game_mode,
    game_subprocess_env,
    is_game_mode,
)
from admapper.core.operator_setup import build_operator_setup


@pytest.fixture(autouse=True)
def _clear_game_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(GAME_MODE_ENV, raising=False)


def test_game_mode_env_disables_sync() -> None:
    assert effective_sync_clock(True) is True
    assert effective_sync_hosts(True) is True
    enable_game_mode()
    assert is_game_mode()
    assert effective_sync_clock(True) is False
    assert effective_sync_hosts(True) is False


def test_game_subprocess_env_sets_flag() -> None:
    env = game_subprocess_env()
    assert env.get(GAME_MODE_ENV) == "1"


def test_operator_setup_hints(tmp_path: Path) -> None:
    setup = build_operator_setup(
        tmp_path,
        dc_ip="10.0.0.1",
        dc_host="dc.lab.htb",
    )
    assert setup["hosts_entry"] == "10.0.0.1  dc.lab.htb"
    assert setup["sync_dc_cmd"] == "admapper sync-dc -H 10.0.0.1"
    assert "sudo sntp" in (setup["sync_clock_cmd"] or "")
