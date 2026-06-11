from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.graph import GraphStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.graph.analyze import run_graph_analysis
from admapper.graph.build import enrich_graph_from_inventory
from admapper.graph.paths import find_attack_paths


def test_find_attack_paths_owned_to_domain_admins() -> None:
    graph = {
        "nodes": [
            {
                "id": "user:jsmith@corp.local",
                "type": "user",
                "username": "jsmith",
                "owned": True,
            },
            {
                "id": "group:it admins@corp.local",
                "type": "group",
                "name": "IT Admins",
            },
            {
                "id": "group:domain admins@corp.local",
                "type": "group",
                "name": "Domain Admins",
                "high_value": True,
            },
        ],
        "edges": [
            {
                "id": "u->g1",
                "source": "user:jsmith@corp.local",
                "target": "group:it admins@corp.local",
                "type": "member_of",
            },
            {
                "id": "g1->g2",
                "source": "group:it admins@corp.local",
                "target": "group:domain admins@corp.local",
                "type": "member_of",
            },
        ],
    }
    paths = find_attack_paths(graph)
    assert paths
    assert paths[0].target == "group:domain admins@corp.local"
    assert paths[0].length == 2


def test_enrich_graph_adds_member_edges() -> None:
    graph = {"nodes": [], "edges": []}
    inventory = {
        "users": [
            {
                "username": "jsmith",
                "dn": "CN=John Smith,OU=Users,DC=corp,DC=local",
            }
        ],
        "groups": [
            {
                "name": "Domain Admins",
                "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
                "members": ["CN=John Smith,OU=Users,DC=corp,DC=local"],
            }
        ],
        "delegations": [],
    }
    enriched = enrich_graph_from_inventory(
        graph,
        inventory,
        domain="corp.local",
        owned_users=["jsmith"],
    )
    edges = enriched["edges"]
    assert any(e["type"] == "member_of" for e in edges)
    owned = [n for n in enriched["nodes"] if n.get("owned")]
    assert owned


def test_run_graph_analysis_writes_paths_json(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    session.workspace.owned_users = ["jsmith"]
    session.persist_workspace()

    store = GraphStore(manager, "lab")
    store.mark_user_owned("corp.local", "jsmith")

    inv = {
        "users": [
            {
                "username": "jsmith",
                "dn": "CN=John Smith,OU=Users,DC=corp,DC=local",
            }
        ],
        "groups": [
            {
                "name": "Domain Admins",
                "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
                "members": ["CN=John Smith,OU=Users,DC=corp,DC=local"],
            }
        ],
        "delegations": [],
        "gpp_credentials": [],
    }
    (tmp_path / "ws" / "lab" / "auth_inventory.json").write_text(
        __import__("json").dumps(inv),
        encoding="utf-8",
    )

    with patch("admapper.graph.analyze.print_manual_guide"):
        result = run_graph_analysis(session)

    assert result.paths
    assert (tmp_path / "ws" / "lab" / "paths.json").is_file()
