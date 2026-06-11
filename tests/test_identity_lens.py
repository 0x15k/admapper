from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.identity_lens import (
    build_identity_lens,
    build_selectable_identities,
    filter_actions_for_pivot,
    filter_targets_for_pivot,
)
from admapper.models.user import UserRecord


def _ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {"username": "alice", "status": "valid", "password": "x"},
                    {"username": "bob", "status": "valid", "password": "y"},
                ]
            }
        )
    )
    (ws / "auth_inventory.json").write_text(
        json.dumps(
            {
                "users": [
                    UserRecord(username="alice", enabled=True, dn="CN=alice,DC=lab,DC=local").to_dict(),
                    UserRecord(username="bob", enabled=True, dn="CN=bob,DC=lab,DC=local").to_dict(),
                    UserRecord(username="carol", enabled=True, kerberoastable=True).to_dict(),
                ]
            }
        )
    )
    (ws / "loot_manifest.json").write_text(
        json.dumps(
            {
                "parsed_credentials": [
                    {
                        "username": "dave",
                        "password": "Winter2024",
                        "source_file": "logs/x.log",
                    }
                ]
            }
        )
    )
    (ws / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}))
    (ws / "acl_findings.json").write_text(json.dumps({"findings": []}))
    return ws


def test_selectable_identities_any_lab(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    rows = build_selectable_identities(ws, domain="lab.local", owned_users=["alice"])
    users = {r["username"] for r in rows}
    assert "alice" in users
    assert "bob" in users
    assert "dave" in users
    assert any(r["username"] == "dave" and r["selectable"] == "verify" for r in rows)
    assert any(r["username"] == "carol" and r["selectable"] == "view" for r in rows)


def test_identity_lens_profiles_pivot(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    lens = build_identity_lens(
        ws,
        workspace="ws",
        domain="lab.local",
        pivot_user="alice",
        owned_users=["alice"],
    )
    assert lens["username"] == "alice"
    assert lens["status"] == "owned_ready"
    assert lens["cred_valid"] is True


def test_identity_lens_enum_target_read_only(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    lens = build_identity_lens(
        ws,
        workspace="ws",
        domain="lab.local",
        pivot_user="carol",
        owned_users=["alice"],
    )
    assert lens["status"] == "enum_target"
    assert lens["read_only"] is True
    assert "kerberoast" in lens["enum_flags"]


def test_filter_actions_for_pivot(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    actions = [
        {"id": "enum", "action": "run", "button": "ENUM"},
        {
            "id": "mission-alice",
            "action": "exploit",
            "button": "GW",
            "mission": {"principal": "alice", "technique": "genericwrite"},
        },
        {
            "id": "mission-bob",
            "action": "exploit",
            "button": "GW",
            "mission": {"principal": "bob", "technique": "genericwrite"},
        },
        {
            "id": "verify_loot",
            "action": "run",
            "button": "VERIFY (dave)",
            "principal": "dave",
        },
    ]
    filtered = filter_actions_for_pivot(actions, pivot="alice")
    ids = {a["id"] for a in filtered}
    assert "enum" in ids
    assert "mission-alice" in ids
    assert "mission-bob" not in ids
    assert "verify_loot" not in ids

    dave_filtered = filter_actions_for_pivot(actions, pivot="dave")
    assert any(a["id"] == "verify_loot" for a in dave_filtered)


def test_filter_targets_for_pivot() -> None:
    targets = [
        {
            "target": "gmsa1",
            "direct_verified": ["alice (genericwrite)"],
            "direct_graph_only": [],
        },
        {
            "target": "gmsa2",
            "direct_verified": ["bob (genericwrite)"],
            "direct_graph_only": [],
        },
    ]
    out = filter_targets_for_pivot(targets, pivot="alice")
    assert len(out) == 1
    assert out[0]["target"] == "gmsa1"
