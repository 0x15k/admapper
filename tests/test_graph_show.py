import json
from pathlib import Path

from admapper.graph.show import build_graph_view


def test_build_graph_view_shows_acl_and_pivot(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "user:svc_sql@corp.local", "type": "user", "username": "svc_sql", "owned": True}], "edges": []}),
        encoding="utf-8",
    )
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "principal": "svc_sql",
                        "right": "genericwrite",
                        "target_name": "msa_health",
                        "severity": "high",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    text = build_graph_view(
        ws,
        domain="corp.local",
        pivot_user="svc_sql",
        owned_users=["svc_sql"],
    )
    assert "ATTACK GRAPH" in text
    assert "genericwrite" in text
    assert "msa_health" in text
