from __future__ import annotations

import json
from pathlib import Path

from admapper.models.hash_record import TgsHash
from admapper.support.workspace import WorkspaceManager


class TgsHashStore:
    """JSON-backed Kerberoast (TGS) hash artifacts."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    @property
    def _path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "kerberoast_hashes.json"

    @property
    def hashcat_export_path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "kerberoast_hashcat.txt"

    def list(self) -> list[TgsHash]:
        if not self._path.is_file():
            return []
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return [TgsHash.from_dict(item) for item in data.get("hashes", [])]

    def save_all(self, hashes: list[TgsHash]) -> Path:
        workspace_dir = self._workspace.path_for(self._workspace_name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        payload = {"hashes": [h.to_dict() for h in hashes]}
        self._path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.export_hashcat(hashes)
        return self._path

    def export_hashcat(self, hashes: list[TgsHash] | None = None) -> Path:
        items = hashes if hashes is not None else self.list()
        lines = [h.hashcat for h in items if h.hashcat]
        path = self.hashcat_export_path
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path

    def merge(self, new_hashes: list[TgsHash]) -> list[TgsHash]:
        by_key: dict[str, TgsHash] = {}
        for h in self.list():
            key = f"{h.domain}\\{h.username}\\{h.spn or ''}".lower()
            by_key[key] = h
        for item in new_hashes:
            key = f"{item.domain}\\{item.username}\\{item.spn or ''}".lower()
            by_key[key] = item
        merged = list(by_key.values())
        self.save_all(merged)
        return merged
