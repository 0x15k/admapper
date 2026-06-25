"""Unit tests for admapper.core.opsec (OPSEC profiles)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from admapper.core.opsec import (
    OpsecProfile,
    OpsecSettings,
    _PROFILES,
    _load_workspace_profile,
    get_opsec,
    save_workspace_profile,
    set_global_profile,
)


# Reset global override between tests
@pytest.fixture(autouse=True)
def _reset_global_profile():
    import admapper.core.opsec as _mod
    _mod._ACTIVE_PROFILE = None
    yield
    _mod._ACTIVE_PROFILE = None


# ── Profile values ────────────────────────────────────────────────────────

def test_stealth_disables_spray():
    s = _PROFILES[OpsecProfile.STEALTH]
    assert s.allow_spray is False
    assert s.allow_coerce is False


def test_stealth_has_delays():
    s = _PROFILES[OpsecProfile.STEALTH]
    assert s.request_delay_min >= 1.0
    assert s.request_delay_max >= s.request_delay_min


def test_lab_has_no_delays():
    s = _PROFILES[OpsecProfile.LAB]
    assert s.request_delay_max == 0.0


def test_lab_disables_confirmations():
    s = _PROFILES[OpsecProfile.LAB]
    assert s.require_confirm("spray") is False
    assert s.require_confirm("coerce") is False
    assert s.require_confirm("dcsync") is False


def test_normal_requires_confirmations():
    s = _PROFILES[OpsecProfile.NORMAL]
    assert s.require_confirm("spray") is True
    assert s.require_confirm("coerce") is True


def test_lab_require_confirm_always_false():
    s = _PROFILES[OpsecProfile.LAB]
    # Even for unknown operations
    assert s.require_confirm("some_unknown_op") is False


def test_normal_require_confirm_unknown_defaults_true():
    s = _PROFILES[OpsecProfile.NORMAL]
    assert s.require_confirm("unknown_operation") is True


# ── sleep_between_requests ────────────────────────────────────────────────

def test_sleep_no_delay_for_lab(monkeypatch):
    calls = []
    monkeypatch.setattr(time, "sleep", lambda n: calls.append(n))
    _PROFILES[OpsecProfile.LAB].sleep_between_requests()
    assert calls == []


def test_sleep_normal_is_fast(monkeypatch):
    calls = []
    monkeypatch.setattr(time, "sleep", lambda n: calls.append(n))
    _PROFILES[OpsecProfile.NORMAL].sleep_between_requests()
    # Normal may sleep 0–0.5s or nothing
    for c in calls:
        assert c <= 0.5


def test_sleep_stealth_delays(monkeypatch):
    calls = []
    monkeypatch.setattr(time, "sleep", lambda n: calls.append(n))
    _PROFILES[OpsecProfile.STEALTH].sleep_between_requests()
    assert len(calls) == 1
    assert calls[0] >= 3.0


# ── save / load workspace profile ─────────────────────────────────────────

def test_save_and_load_workspace_profile(tmp_path: Path) -> None:
    save_workspace_profile(tmp_path, OpsecProfile.STEALTH)
    loaded = _load_workspace_profile(tmp_path)
    assert loaded == OpsecProfile.STEALTH


def test_save_overwrites_existing(tmp_path: Path) -> None:
    save_workspace_profile(tmp_path, OpsecProfile.LAB)
    save_workspace_profile(tmp_path, OpsecProfile.STEALTH)
    assert _load_workspace_profile(tmp_path) == OpsecProfile.STEALTH


def test_load_returns_none_when_no_state(tmp_path: Path) -> None:
    assert _load_workspace_profile(tmp_path) is None


def test_load_returns_none_for_invalid_profile(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text(
        json.dumps({"opsec_profile": "ultra-secret"}), encoding="utf-8"
    )
    assert _load_workspace_profile(tmp_path) is None


# ── get_opsec ─────────────────────────────────────────────────────────────

def test_get_opsec_global_override() -> None:
    set_global_profile(OpsecProfile.STEALTH)
    settings = get_opsec(session=None)
    assert settings.profile == OpsecProfile.STEALTH


def test_get_opsec_from_workspace(tmp_path: Path) -> None:
    save_workspace_profile(tmp_path, OpsecProfile.LAB)

    ws = MagicMock()
    ws.name = "test"
    workspaces = MagicMock()
    workspaces.path_for.return_value = tmp_path
    session = MagicMock()
    session.workspace = ws
    session.workspaces = workspaces

    settings = get_opsec(session)
    assert settings.profile == OpsecProfile.LAB


def test_get_opsec_defaults_to_normal() -> None:
    settings = get_opsec(session=None)
    assert settings.profile == OpsecProfile.NORMAL


def test_global_override_takes_priority(tmp_path: Path) -> None:
    save_workspace_profile(tmp_path, OpsecProfile.LAB)

    ws = MagicMock()
    ws.name = "test"
    workspaces = MagicMock()
    workspaces.path_for.return_value = tmp_path
    session = MagicMock()
    session.workspace = ws
    session.workspaces = workspaces

    set_global_profile(OpsecProfile.STEALTH)
    settings = get_opsec(session)
    assert settings.profile == OpsecProfile.STEALTH


# ── to_dict ───────────────────────────────────────────────────────────────

def test_opsec_settings_to_dict() -> None:
    s = _PROFILES[OpsecProfile.NORMAL]
    d = s.to_dict()
    assert d["profile"] == "normal"
    assert "allow_spray" in d
    assert "confirm_coerce" in d
    assert "ldap_page_size" in d
