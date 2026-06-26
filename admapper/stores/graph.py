from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from admapper.support.workspace import WorkspaceManager


class GraphStore:
    """Minimal attack graph with owned-user tracking (Phase 7)."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    @property
    def path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "graph.json"

    def load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"nodes": [], "edges": []}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, graph: dict[str, Any]) -> Path:
        workspace_dir = self._workspace.path_for(self._workspace_name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(graph, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self.path

    def mark_user_owned(
        self,
        domain: str,
        username: str,
        *,
        cred_id: str | None = None,
    ) -> dict[str, Any]:
        """Add or update an owned user node in graph.json."""
        graph = self.load()
        node_id = f"user:{username.lower()}@{domain.lower()}"
        domain_id = f"domain:{domain.lower()}"

        nodes: list[dict[str, Any]] = list(graph.get("nodes", []))
        edges: list[dict[str, Any]] = list(graph.get("edges", []))

        nodes = [n for n in nodes if n.get("id") != node_id]
        nodes.append(
            {
                "id": node_id,
                "type": "user",
                "username": username,
                "domain": domain.lower(),
                "owned": True,
                "labels": ["owned"],
                "credential_id": cred_id,
            }
        )

        if not any(n.get("id") == domain_id for n in nodes):
            nodes.append(
                {
                    "id": domain_id,
                    "type": "domain",
                    "name": domain.lower(),
                    "owned": False,
                }
            )

        edge_id = f"{node_id}->member_of->{domain_id}"
        edges = [e for e in edges if e.get("id") != edge_id]
        edges.append(
            {
                "id": edge_id,
                "source": node_id,
                "target": domain_id,
                "type": "member_of_domain",
            }
        )

        graph["nodes"] = nodes
        graph["edges"] = edges
        self.save(graph)
        return graph
