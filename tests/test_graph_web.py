import json
from pathlib import Path

from admapper.graph.web import build_attack_graph_html, write_attack_graph_html


def test_attack_graph_html(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "graph.json").write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "id": "user:svc_sql@corp.local",
                        "type": "user",
                        "username": "svc_sql",
                        "owned": True,
                    },
                    {
                        "id": "group:protected users@corp.local",
                        "type": "group",
                        "name": "Protected Users",
                    },
                ],
                "edges": [
                    {
                        "source": "user:svc_sql@corp.local",
                        "target": "group:protected users@corp.local",
                        "type": "member_of",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "user_intel.json").write_text(
        json.dumps(
            {
                "users": [
                    {
                        "username": "svc_sql",
                        "sources": ["ldap_auth", "share_loot"],
                        "in_domain": True,
                        "cred_status": "valid",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    html = build_attack_graph_html(
        ws,
        workspace="ws",
        domain="corp.local",
        owned_users=["svc_sql"],
        pivot_user="svc_sql",
    )
    assert "vis-network" in html
    assert "svc_sql" in html
    assert "ldap_auth" in html
    assert "Estás aquí" in html
    assert "Siguiente paso" in html or "Hash obtenido" in html


def test_attack_graph_html_shows_hash_and_krb5_blocker(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {
                        "account": "msa_health$",
                        "nthash": "0123456789abcdef0123456789abcdef",
                    }
                ],
                "steps": [
                    {
                        "phase": "acl_exploit",
                        "status": "skipped",
                        "detail": "kinit failed: MIT krb5 not found",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    html = build_attack_graph_html(
        ws,
        workspace="ws",
        domain="corp.local",
        owned_users=["msa_health$"],
        pivot_user="msa_health$",
    )
    assert "Hash obtenido" in html
    assert "0123456789abcdef0123456789abcdef" in html
    assert "dc01.corp.local" in html
    assert "Bloqueo" in html
    assert "WinRM" in html

    path = write_attack_graph_html(
        ws,
        workspace="ws",
        domain="corp.local",
        owned_users=["svc_sql"],
        pivot_user="svc_sql",
    )
    assert path.name == "attack_graph.html"
