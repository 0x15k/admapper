from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from admapper.support.workspace import WorkspaceManager
from admapper.models.ad_object import (
    ComputerRecord,
    DelegationRecord,
    GpoRecord,
    GppCredential,
    GroupRecord,
    OuRecord,
    TrustRecord,
)
from admapper.models.user import UserRecord


class AuthInventoryStore:
    """Phase 8 authenticated enumeration artefacts."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    def _dir(self) -> Path:
        path = self._workspace.path_for(self._workspace_name)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def inventory_path(self) -> Path:
        return self._dir() / "auth_inventory.json"

    def load(self) -> dict[str, Any] | None:
        if not self.inventory_path.is_file():
            return None
        return json.loads(self.inventory_path.read_text(encoding="utf-8"))

    def save(
        self,
        *,
        users: list[UserRecord],
        groups: list[GroupRecord],
        computers: list[ComputerRecord],
        ous: list[OuRecord],
        gpos: list[GpoRecord],
        delegations: list[DelegationRecord],
        trusts: list[TrustRecord],
        gpp_credentials: list[GppCredential],
        smb_shares: list[str],
        adcs_present: bool,
        errors: list[str],
        extra: dict[str, Any] | None = None,
    ) -> Path:
        payload: dict[str, Any] = {
            "users": [u.to_dict() for u in users],
            "groups": [g.to_dict() for g in groups],
            "computers": [c.to_dict() for c in computers],
            "ous": [o.to_dict() for o in ous],
            "gpos": [g.to_dict() for g in gpos],
            "delegations": [d.to_dict() for d in delegations],
            "trusts": [t.to_dict() for t in trusts],
            "gpp_credentials": [g.to_dict() for g in gpp_credentials],
            "smb_shares": smb_shares,
            "adcs_present": adcs_present,
            "errors": errors,
        }
        if extra:
            payload.update(extra)
        self.inventory_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self.inventory_path
