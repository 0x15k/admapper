from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep global config under the pytest temp dir."""
    cfg_dir = tmp_path / ".admapper"
    cfg_dir.mkdir()
    cfg_path = cfg_dir / "config.json"
    monkeypatch.setattr("admapper.core.config.global_config_path", lambda: cfg_path)
    return cfg_path
