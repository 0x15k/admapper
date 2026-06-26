from pathlib import Path

from admapper.core.graph import GraphStore
from admapper.core.workspace import WorkspaceManager


def test_graph_marks_owned_user(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    manager.create("lab")
    store = GraphStore(manager, "lab")

    graph = store.mark_user_owned("target.example", "jsmith", cred_id="abc123")
    assert any(n.get("owned") and n.get("username") == "jsmith" for n in graph["nodes"])
    assert any(n.get("type") == "domain" for n in graph["nodes"])
    assert graph["edges"]

    reloaded = store.load()
    assert reloaded["nodes"]
