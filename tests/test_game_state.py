from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.game_state import (
    build_objective_game_state,
    explain_target_access,
)


def test_need_creds_stage(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps({"hosts": [{"address": "10.0.0.1", "is_domain_controller": True}]})
    )
    state = build_objective_game_state(
        ws, workspace="ws", domain="lab.htb", owned_users=[], pivot_user=None
    )
    assert state["stage"] == "need_creds"
    assert state["game_over"] is True
    assert state["actions"][0]["action"] == "run"


def test_only_svc_recovery_verified_for_msa(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "graph.json").write_text(
        json.dumps(
            {
                "nodes": [],
                "edges": [
                    {
                        "source": "user:wallace@lab.htb",
                        "target": "computer:msa_health.lab.htb",
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
                        "principal": "svc_recovery",
                        "right": "genericwrite",
                        "target_name": "msa_health",
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
                    {"username": "wallace", "status": "valid"},
                    {"username": "svc_recovery", "status": "valid"},
                ]
            }
        )
    )
    info = explain_target_access(
        ws, domain="lab.htb", target="msa_health", owned_users=["wallace", "svc_recovery"]
    )
    assert any("svc_recovery" in v for v in info["direct_verified"])
    assert not any("wallace" in v for v in info["direct_verified"])
    assert any("wallace" in v for v in info["direct_graph_only"])
