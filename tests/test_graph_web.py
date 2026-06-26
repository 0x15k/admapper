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
                        "id": "user:svc_user@target.example",
                        "type": "user",
                        "username": "svc_user",
                        "owned": True,
                    },
                    {
                        "id": "group:protected users@target.example",
                        "type": "group",
                        "name": "Protected Users",
                    },
                ],
                "edges": [
                    {
                        "source": "user:svc_user@target.example",
                        "target": "group:protected users@target.example",
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
                        "username": "svc_user",
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
        domain="target.example",
        owned_users=["svc_user"],
        pivot_user="svc_user",
    )
    assert "vis-network" in html
    assert "svc_user" in html
    assert "ldap_auth" in html
    assert "You are here" in html
    assert "Next step" in html or "Hash obtained" in html


def test_attack_graph_html_shows_hash_and_krb5_blocker(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {
                        "account": "msa_target$",
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
        domain="target.example",
        owned_users=["msa_target$"],
        pivot_user="msa_target$",
    )
    assert "Hash obtained" in html
    assert "0123456789abcdef0123456789abcdef" in html
    assert "dc01.target.example" in html
    assert "Blocker" in html
    assert "WinRM" in html

    path = write_attack_graph_html(
        ws,
        workspace="ws",
        domain="target.example",
        owned_users=["svc_user"],
        pivot_user="svc_user",
    )
    assert path.name == "attack_graph.html"
