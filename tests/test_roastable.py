"""Unit tests for admapper.enumeration.roastable (Fase 3)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from admapper.enumeration.roastable import (
    RoastableReport,
    _load_users,
    detect_roastable_targets,
)
from admapper.models.user import UserRecord


def _make_user(
    username: str,
    *,
    uac: int | None = None,
    spns: list[str] | None = None,
    asrep: bool = False,
    kerb: bool = False,
    enabled: bool = True,
) -> UserRecord:
    u = UserRecord(username=username, uac=uac, spns=spns or [], enabled=enabled)
    u.asrep_roastable = asrep
    u.kerberoastable = kerb
    return u


# ── _load_users ───────────────────────────────────────────────────────────

def test_load_users_from_auth_inventory(tmp_path: Path) -> None:
    inv = {
        "users": [
            {"username": "alice", "asrep_roastable": True, "enabled": True},
            {"username": "bob", "kerberoastable": True, "spns": ["cifs/srv01"], "enabled": True},
        ]
    }
    (tmp_path / "auth_inventory.json").write_text(json.dumps(inv), encoding="utf-8")
    users = _load_users(tmp_path)
    assert len(users) == 2
    assert users[0].username == "alice"


def test_load_users_fallback_to_users_json(tmp_path: Path) -> None:
    users_data = {
        "users": [
            {"username": "charlie", "enabled": True},
        ]
    }
    (tmp_path / "users.json").write_text(json.dumps(users_data), encoding="utf-8")
    users = _load_users(tmp_path)
    assert len(users) == 1
    assert users[0].username == "charlie"


def test_load_users_empty_when_no_files(tmp_path: Path) -> None:
    assert _load_users(tmp_path) == []


# ── detect_roastable_targets ──────────────────────────────────────────────

def _make_session(ws_path: Path, ws_name: str = "test") -> MagicMock:
    ws = MagicMock()
    ws.name = ws_name

    workspaces = MagicMock()
    workspaces.path_for.return_value = ws_path

    session = MagicMock()
    session.workspace = ws
    session.workspaces = workspaces
    return session


def test_detect_roastable_targets_asrep(tmp_path: Path) -> None:
    inv = {
        "users": [
            {
                "username": "asrep_user",
                "asrep_roastable": True,
                "enabled": True,
                "uac": 0x400000,
            }
        ]
    }
    (tmp_path / "auth_inventory.json").write_text(json.dumps(inv), encoding="utf-8")

    session = _make_session(tmp_path)
    findings_store = MagicMock()
    findings_store.merge = MagicMock()
    session.workspaces.path_for.return_value = tmp_path

    with patch("admapper.enumeration.roastable.FindingsStore", return_value=findings_store):
        report = detect_roastable_targets(session)

    assert len(report.asrep_targets) == 1
    assert report.asrep_targets[0].username == "asrep_user"
    assert (tmp_path / "roastable_targets.json").is_file()


def test_detect_roastable_targets_kerberoast(tmp_path: Path) -> None:
    inv = {
        "users": [
            {
                "username": "svc_sql",
                "kerberoastable": True,
                "spns": ["MSSQLSvc/db01:1433"],
                "enabled": True,
            }
        ]
    }
    (tmp_path / "auth_inventory.json").write_text(json.dumps(inv), encoding="utf-8")

    session = _make_session(tmp_path)
    with patch("admapper.enumeration.roastable.FindingsStore", return_value=MagicMock()):
        report = detect_roastable_targets(session)

    assert len(report.kerberoast_targets) == 1
    assert report.kerberoast_targets[0].username == "svc_sql"


def test_detect_roastable_targets_passwd_notreqd(tmp_path: Path) -> None:
    inv = {
        "users": [
            {
                "username": "nopasswd",
                "password_not_required": True,
                "enabled": True,
                "uac": 0x20,
            }
        ]
    }
    (tmp_path / "auth_inventory.json").write_text(json.dumps(inv), encoding="utf-8")

    session = _make_session(tmp_path)
    with patch("admapper.enumeration.roastable.FindingsStore", return_value=MagicMock()):
        report = detect_roastable_targets(session)

    assert len(report.password_not_required) == 1


def test_detect_roastable_targets_machine_accounts_excluded(tmp_path: Path) -> None:
    inv = {
        "users": [
            {
                "username": "COMPUTER01$",
                "asrep_roastable": True,
                "enabled": True,
            }
        ]
    }
    (tmp_path / "auth_inventory.json").write_text(json.dumps(inv), encoding="utf-8")

    session = _make_session(tmp_path)
    with patch("admapper.enumeration.roastable.FindingsStore", return_value=MagicMock()):
        report = detect_roastable_targets(session)

    # Machine accounts should be excluded from human_users
    assert len(report.asrep_targets) == 0


def test_detect_roastable_targets_no_workspace() -> None:
    session = MagicMock()
    session.workspace = None
    with pytest.raises(RuntimeError, match="no active workspace"):
        detect_roastable_targets(session)


def test_detect_roastable_targets_no_inventory(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    report = detect_roastable_targets(session)
    assert report.asrep_targets == []
    assert report.kerberoast_targets == []


def test_detect_roastable_uac_backfill(tmp_path: Path) -> None:
    """UAC 0x400000 should set asrep_roastable even if flag was False."""
    inv = {
        "users": [
            {
                "username": "flagged",
                "asrep_roastable": False,
                "enabled": True,
                "uac": 0x400000,  # DONT_REQ_PREAUTH
            }
        ]
    }
    (tmp_path / "auth_inventory.json").write_text(json.dumps(inv), encoding="utf-8")

    session = _make_session(tmp_path)
    with patch("admapper.enumeration.roastable.FindingsStore", return_value=MagicMock()):
        report = detect_roastable_targets(session)

    assert len(report.asrep_targets) == 1
    assert report.asrep_targets[0].username == "flagged"


def test_roastable_report_output_json(tmp_path: Path) -> None:
    inv = {
        "users": [
            {"username": "a_asrep", "asrep_roastable": True, "enabled": True},
            {"username": "b_kerb", "kerberoastable": True, "spns": ["http/srv"], "enabled": True},
        ]
    }
    (tmp_path / "auth_inventory.json").write_text(json.dumps(inv), encoding="utf-8")

    session = _make_session(tmp_path)
    with patch("admapper.enumeration.roastable.FindingsStore", return_value=MagicMock()):
        detect_roastable_targets(session)

    out = json.loads((tmp_path / "roastable_targets.json").read_text())
    assert "a_asrep" in out["asrep_targets"]
    assert "b_kerb" in out["kerberoast_targets"]
