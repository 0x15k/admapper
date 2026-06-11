import json
from pathlib import Path

from admapper.graph.show import build_graph_view


def test_build_graph_view_shows_acl_and_pivot(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "user:svc_recovery@logging.htb", "type": "user", "username": "svc_recovery", "owned": True}], "edges": []}),
        encoding="utf-8",
    )
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "principal": "svc_recovery",
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
        domain="logging.htb",
        pivot_user="svc_recovery",
        owned_users=["svc_recovery"],
    )
    assert "GRAFO DE ATAQUE" in text
    assert "genericwrite" in text
    assert "msa_health" in text
