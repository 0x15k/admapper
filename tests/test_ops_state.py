from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.ops_state import (
    build_objective_ops_state,
    explain_target_access,
)


def test_need_creds_stage(tmp_path: Path) -> None:
    """With scan + users but no creds → need_creds stage."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps({"hosts": [{"address": "10.0.0.1", "is_domain_controller": True}]})
    )
    (ws / "users.json").write_text(
        json.dumps({"users": [{"username": "target"}, {"username": "admin"}]})
    )
    state = build_objective_ops_state(
        ws, workspace="ws", domain="target.example", owned_users=[], pivot_user=None
    )
    assert state["stage"] == "need_creds"
    assert state["engagement_over"] is False
    action_ids = {a["action"] for a in state["actions"]}
    assert "run" in action_ids
    assert any(a.get("required") for a in state["actions"])


def test_enum_stage_no_users(tmp_path: Path) -> None:
    """With scan but no users and no creds → enum stage."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps({"hosts": [{"address": "10.0.0.1", "is_domain_controller": True}]})
    )
    state = build_objective_ops_state(
        ws, workspace="ws", domain="target.example", owned_users=[], pivot_user=None
    )
    assert state["stage"] == "enum"
    assert state["engagement_over"] is False
    action_ids = {a["action"] for a in state["actions"]}
    assert "enum" in action_ids
    assert any(a.get("required") for a in state["actions"])


def test_only_sql_service_verified_for_msa(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "graph.json").write_text(
        json.dumps(
            {
                "nodes": [],
                "edges": [
                    {
                        "source": "user:target@target.example",
                        "target": "computer:msa_target.target.example",
                        "type": "genericwrite",
                    }
                ],
            }
        )
    )
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "acl-1",
                        "principal": "svc_user",
                        "right": "genericwrite",
                        "target_name": "msa_target",
                        "summary": "gMSA abuse",
                    }
                ]
            }
        )
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {"username": "target", "status": "valid"},
                    {"username": "svc_user", "status": "valid"},
                ]
            }
        )
    )
    info = explain_target_access(
        ws, domain="target.example", target="msa_target", owned_users=["target", "svc_user"]
    )
    assert any("svc_user" in v for v in info["direct_verified"])
    assert not any("target" in v for v in info["direct_verified"])
    assert any("target" in v for v in info["direct_graph_only"])
