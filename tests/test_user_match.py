import json
from pathlib import Path

from admapper.intel.user_match import build_user_intel


def test_user_match_loot_with_ldap(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "users.json").write_text(
        json.dumps(
            {
                "users": [
                    {
                        "username": "svc_recovery",
                        "sources": ["ldap_auth"],
                        "enabled": True,
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
                    {
                        "username": "svc_recovery",
                        "password": "Em3rg3ncyPa$$2025",
                        "source_file": "Logs/trace.log",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "username": "svc_recovery",
                        "status": "valid",
                        "secret": "x",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    intel = build_user_intel(ws)
    assert intel["user_count"] == 1
    user = intel["users"][0]
    assert "ldap_auth" in user["sources"]
    assert "share_loot" in user["sources"]
    assert user["in_domain"] is True
    assert user["cred_status"] == "valid"
    assert user["loot_password"] == "Em3rg3ncyPa$$2025"
