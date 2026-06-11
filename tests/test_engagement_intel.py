from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from admapper.analysis.engagement_intel import build_engagement_intel
from admapper.models.spray import DomainLockoutPolicy
from admapper.models.user import UserRecord


def _ws_with_inventory(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "address": "10.0.0.1",
                        "is_domain_controller": True,
                    }
                ]
            }
        )
    )
    (ws / "auth_inventory.json").write_text(
        json.dumps(
            {
                "users": [
                    UserRecord(
                        username="alice",
                        enabled=True,
                        kerberoastable=True,
                        spns=["HTTP/dc"],
                        dn="CN=alice,DC=lab,DC=local",
                    ).to_dict(),
                    UserRecord(
                        username="bob",
                        enabled=True,
                        asrep_roastable=True,
                        dn="CN=bob,DC=lab,DC=local",
                    ).to_dict(),
                    UserRecord(username="DC01$", enabled=True).to_dict(),
                ]
            }
        )
    )
    (ws / "loot_manifest.json").write_text(
        json.dumps(
            {
                "parsed_credentials": [
                    {
                        "username": "alice",
                        "password": "Winter2024",
                        "source_file": "Logs/sync_20250101.log",
                        "confidence": "medium",
                    }
                ]
            }
        )
    )
    return ws


def test_build_engagement_intel_domain_users(tmp_path: Path) -> None:
    ws = _ws_with_inventory(tmp_path)
    policy = DomainLockoutPolicy(
        lockout_threshold=5,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
        source_host="10.0.0.1",
    )
    (ws / "lockout_policy.json").write_text(
        json.dumps(
            {
                "policy": policy.to_dict(),
                "user_states": [
                    {"username": "alice", "bad_pwd_count": 2, "lockout_time": 0},
                    {"username": "bob", "bad_pwd_count": 4, "lockout_time": 0},
                ],
            }
        )
    )
    intel = build_engagement_intel(ws, workspace="ws", domain="lab.local", owned_users=["alice"])

    users = intel["domain_users"]
    assert len(users) == 2
    alice = next(u for u in users if u["username"] == "alice")
    assert alice["kerberoastable"] is True
    assert alice["attempts_remaining"] == 3
    bob = next(u for u in users if u["username"] == "bob")
    assert bob["asrep_roastable"] is True
    assert bob["attempts_remaining"] == 1

    spray = intel["spray_safety"]
    assert "alice" in spray["eligible"]
    assert any("bob" in s for s in spray["skipped"])

    assert intel["password_analysis"]["rules"]
    assert intel["identity_capabilities"]
    assert intel["attack_readiness"]
    assert any(v["attack_id"] == "passwordspray" for v in intel["attack_readiness"])


def test_lockout_policy_cached(tmp_path: Path) -> None:
    ws = _ws_with_inventory(tmp_path)
    (ws / "lockout_policy.json").write_text(
        json.dumps(
            {
                "policy": DomainLockoutPolicy(lockout_threshold=3, source_host="10.0.0.1").to_dict(),
                "user_states": [{"username": "alice", "bad_pwd_count": 1, "lockout_time": 0}],
            }
        )
    )
    with patch("admapper.analysis.engagement_intel.fetch_lockout_context") as mock_fetch:
        intel = build_engagement_intel(ws, domain="lab.local")
        mock_fetch.assert_not_called()

    alice = next(u for u in intel["domain_users"] if u["username"] == "alice")
    assert alice["bad_pwd_count"] == 1
    assert alice["attempts_remaining"] == 2
