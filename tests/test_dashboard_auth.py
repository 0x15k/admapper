"""Tests for game-only credential auth (no start_auth chain)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.session import Session
from admapper.graph.game_auth import run_game_credential_auth
from admapper.models.credential import Credential, CredentialStatus


def _session(tmp_path: Path) -> Session:
    root = tmp_path / "workspaces"
    ws = root / "target-lab"
    ws.mkdir(parents=True)
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "address": "10.0.0.1",
                        "hostname": "dc01.lab.htb",
                        "is_domain_controller": True,
                        "open_ports": [389, 445],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "hosts.json").write_text(
        json.dumps({"hosts": [{"address": "10.0.0.1", "is_domain_controller": True}]}),
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "id": "old-wallace",
                        "username": "wallace.everette",
                        "secret": "x",
                        "domain": "lab.htb",
                        "status": "valid",
                        "cred_type": "password",
                        "source": "cli",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    session = Session.bootstrap(workspaces_root=root)
    session.select_workspace("target-lab", create=True)
    session.set_domain("lab.htb")
    return session


def test_game_auth_verifies_submitted_user_not_first_valid(tmp_path: Path) -> None:
    session = _session(tmp_path)
    verified = Credential(
        id="new-svc",
        username="svc_recovery",
        secret="pw",
        domain="lab.htb",
        status=CredentialStatus.VALID,
    )

    with (
        patch("admapper.graph.game_auth.pick_dc_ip", return_value="10.0.0.1"),
        patch("admapper.graph.game_auth.ensure_dc_clock"),
        patch("admapper.graph.game_auth.run_credential_verify") as mock_verify,
        patch("admapper.graph.game_auth.set_pivot_user") as mock_pivot,
    ):
        mock_verify.return_value.credential = verified

        result = run_game_credential_auth(
            session,
            username="svc_recovery",
            password="Em3rg3ncyPa$$2026",
            domain="lab.htb",
        )

    assert result.username == "svc_recovery"
    added = session.credentials.list()
    assert any(c.username == "svc_recovery" for c in added)
    mock_verify.assert_called_once()
    called_id = mock_verify.call_args[0][1]
    assert any(c.id == called_id and c.username == "svc_recovery" for c in added)
    mock_pivot.assert_called_once_with(session, "svc_recovery")
