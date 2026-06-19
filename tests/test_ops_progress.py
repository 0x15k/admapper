from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.game_payload import build_game_payload
from admapper.graph.game_progress import GameProgress


def _polluted_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps({"domain": "lab.htb", "hosts": [{"address": "10.0.0.1", "is_domain_controller": True}]}),
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "username": "svc_recovery",
                        "secret": "secret",
                        "status": "valid",
                        "type": "password",
                        "domain": "lab.htb",
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
                    {"username": "svc_recovery", "password": "Em3rg3ncyPa$$2025", "confidence": "medium"}
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
                        "principal": "svc_recovery",
                        "right": "genericwrite",
                        "target_name": "msa_health",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "state.json").write_text(
        json.dumps({"owned_users": ["svc_recovery", "wallace.everette"], "pivot_user": "svc_recovery"}),
        encoding="utf-8",
    )
    return ws


def test_fresh_game_progress_hides_cli_spoilers(tmp_path: Path) -> None:
    ws = _polluted_workspace(tmp_path)
    progress = GameProgress.fresh()
    data = build_game_payload(
        ws,
        workspace="ws",
        domain="lab.htb",
        game_progress=progress,
    )
    assert data["meta"]["blackbox"] is True
    assert data["creds"] == []
    assert data["clues"] == []
    assert data["player"]["owned"] == []
    assert not any(i["username"] == "svc_recovery" for i in data["selectable_identities"])


def test_progress_after_auth_shows_only_player_cred(tmp_path: Path) -> None:
    ws = _polluted_workspace(tmp_path)
    progress = GameProgress.fresh()
    progress.scan = True
    progress.remember_auth("wallace.everette")
    data = build_game_payload(
        ws,
        workspace="ws",
        domain="lab.htb",
        game_progress=progress,
        pivot_user="wallace.everette",
    )
    assert len(data["creds"]) == 1
    assert data["creds"][0]["user"] == "wallace.everette"
    assert not any(c["user"] == "svc_recovery" for c in data["creds"])


def test_progress_hides_hashes_until_exploit(tmp_path: Path) -> None:
    ws = _polluted_workspace(tmp_path)
    (ws / "state.json").write_text(
        json.dumps({"owned_users": ["svc_recovery"], "pivot_user": "svc_recovery"}),
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
    progress = GameProgress.fresh()
    progress.scan = True
    progress.remember_auth("svc_recovery")
    progress.acls = True
    data = build_game_payload(
        ws,
        workspace="ws",
        domain="lab.htb",
        game_progress=progress,
        pivot_user="svc_recovery",
    )
    assert data["hashes"] == []
    assert data["progress"]["exploit"] is False

    progress.exploit = True
    data = build_game_payload(
        ws,
        workspace="ws",
        domain="lab.htb",
        game_progress=progress,
        pivot_user="svc_recovery",
    )
    assert len(data["hashes"]) >= 1
