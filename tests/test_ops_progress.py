from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.ops_payload import build_ops_payload
from admapper.graph.ops_progress import OpsProgress


def _polluted_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps({"domain": "corp.local", "hosts": [{"address": "10.0.0.1", "is_domain_controller": True}]}),
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "username": "svc_sql",
                        "secret": "secret",
                        "status": "valid",
                        "type": "password",
                        "domain": "corp.local",
                        "source": "cli",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "loot_manifest.json").write_text(
        json.dumps(
            {
                "parsed_credentials": [
                    {"username": "svc_sql", "password": "WelcomePassword123!", "confidence": "medium"}
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "acl-001",
                        "principal": "svc_sql",
                        "right": "genericwrite",
                        "target_name": "msa_health",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "state.json").write_text(
        json.dumps({"owned_users": ["svc_sql", "wallace.doe"], "pivot_user": "svc_sql"}),
        encoding="utf-8",
    )
    return ws


def test_fresh_ops_progress_hides_cli_spoilers(tmp_path: Path) -> None:
    ws = _polluted_workspace(tmp_path)
    progress = OpsProgress.fresh()
    data = build_ops_payload(
        ws,
        workspace="ws",
        domain="corp.local",
        ops_progress=progress,
    )
    assert data["meta"]["blackbox"] is True
    assert data["creds"] == []
    assert data["clues"] == []
    assert data["player"]["owned"] == []
    assert not any(i["username"] == "svc_sql" for i in data["selectable_identities"])


def test_progress_after_auth_shows_only_player_cred(tmp_path: Path) -> None:
    ws = _polluted_workspace(tmp_path)
    progress = OpsProgress.fresh()
    progress.scan = True
    progress.remember_auth("wallace.doe")
    data = build_ops_payload(
        ws,
        workspace="ws",
        domain="corp.local",
        ops_progress=progress,
        pivot_user="wallace.doe",
    )
    assert len(data["creds"]) == 1
    assert data["creds"][0]["user"] == "wallace.doe"
    assert not any(c["user"] == "svc_sql" for c in data["creds"])


def test_progress_hides_hashes_until_exploit(tmp_path: Path) -> None:
    ws = _polluted_workspace(tmp_path)
    (ws / "state.json").write_text(
        json.dumps({"owned_users": ["svc_sql"], "pivot_user": "svc_sql"}),
        encoding="utf-8",
    )
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {
                        "account": "msa_health$",
                        "nthash": "aad3b435b51404eeaad3b435b51404ee",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    progress = OpsProgress.fresh()
    progress.scan = True
    progress.remember_auth("svc_sql")
    progress.acls = True
    data = build_ops_payload(
        ws,
        workspace="ws",
        domain="corp.local",
        ops_progress=progress,
        pivot_user="svc_sql",
    )
    assert data["hashes"] == []
    assert data["progress"]["exploit"] is False

    progress.exploit = True
    data = build_ops_payload(
        ws,
        workspace="ws",
        domain="corp.local",
        ops_progress=progress,
        pivot_user="svc_sql",
    )
    assert len(data["hashes"]) >= 1
