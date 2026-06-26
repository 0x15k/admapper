"""Tests for dashboard credential auth (no start_auth chain)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.session import Session
from admapper.graph.dashboard_auth import run_dashboard_credential_auth
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
                        "hostname": "dc01.corp.local",
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
                        "username": "wallace.doe",
                        "secret": "x",
                        "domain": "corp.local",
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
    session.set_domain("corp.local")
    return session


def test_dashboard_auth_verifies_submitted_user_not_first_valid(tmp_path: Path) -> None:
    session = _session(tmp_path)
    verified = Credential(
        id="new-svc",
        username="svc_sql",
        secret="pw",
        domain="corp.local",
        status=CredentialStatus.VALID,
    )

    with (
        patch("admapper.graph.dashboard_auth.pick_dc_ip", return_value="10.0.0.1"),
        patch("admapper.graph.dashboard_auth.ensure_dc_clock"),
        patch("admapper.graph.dashboard_auth.run_credential_verify") as mock_verify,
        patch("admapper.graph.dashboard_auth.set_pivot_user") as mock_pivot,
    ):
        mock_verify.return_value.credential = verified

        result = run_dashboard_credential_auth(
            session,
            username="svc_sql",
            password="WelcomePassword123!",
            domain="corp.local",
        )

    assert result.username == "svc_sql"
    added = session.credentials.list()
    assert any(c.username == "svc_sql" for c in added)
    mock_verify.assert_called_once()
    called_id = mock_verify.call_args[0][1]
    assert any(c.id == called_id and c.username == "svc_sql" for c in added)
    mock_pivot.assert_called_once_with(session, "svc_sql")


def test_dashboard_auth_uses_session_target_ip_when_ip_missing(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.workspace.hosts = "10.0.0.1"
    session.persist_workspace()

    verified = Credential(
        id="new-svc",
        username="svc_sql",
        secret="pw",
        domain="corp.local",
        status=CredentialStatus.VALID,
    )

    with (
        patch("admapper.graph.dashboard_auth.pick_dc_ip", return_value="10.0.0.1"),
        patch("admapper.graph.dashboard_auth.ensure_dc_clock"),
        patch("admapper.graph.dashboard_auth.run_credential_verify") as mock_verify,
        patch("admapper.graph.dashboard_auth.set_pivot_user"),
    ):
        mock_verify.return_value.credential = verified

        run_dashboard_credential_auth(
            session,
            username="svc_sql",
            password="WelcomePassword123!",
            domain="corp.local",
        )

    added = session.credentials.list()
    assert any(c.username == "svc_sql" for c in added)
