from __future__ import annotations

import json
import os
from pathlib import Path

from admapper.core.workspace import WorkspaceManager
from admapper.models.credential import Credential, CredentialStatus, CredentialType


class CredentialStore:
    """JSON-backed credential list for the active workspace."""

    def __init__(self, workspace: WorkspaceManager, workspace_name: str) -> None:
        self._workspace = workspace
        self._workspace_name = workspace_name

    @property
    def _path(self) -> Path:
        return self._workspace.path_for(self._workspace_name) / "credentials.json"

    def list(self) -> list[Credential]:
        if not self._path.is_file():
            return []
        data = json.loads(self._path.read_text(encoding="utf-8"))
        items = data.get("credentials", [])
        return [Credential.from_dict(item) for item in items]

    def save_all(self, credentials: list[Credential]) -> Path:
        workspace_dir = self._workspace.path_for(self._workspace_name)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        payload = {"credentials": [c.to_dict() for c in credentials]}
        self._path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(self._path, 0o600)
        return self._path

    def add(
        self,
        username: str,
        secret: str,
        *,
        domain: str | None = None,
        cred_type: CredentialType = CredentialType.PASSWORD,
        source: str = "manual",
    ) -> Credential:
        credentials = self.list()
        existing = next(
            (c for c in credentials if c.username.lower() == username.strip().lower()),
            None,
        )
        if existing is not None:
            credentials = [c for c in credentials if c.id != existing.id]
        cred = Credential(
            username=username.strip(),
            secret=secret,
            domain=domain,
            cred_type=cred_type,
            source=source,
        )
        credentials.append(cred)
        self.save_all(credentials)
        return cred

    def remove(self, cred_id: str) -> bool:
        credentials = self.list()
        filtered = [c for c in credentials if c.id != cred_id]
        if len(filtered) == len(credentials):
            return False
        self.save_all(filtered)
        return True

    def mark_status(self, cred_id: str, status: CredentialStatus) -> Credential | None:
        credentials = self.list()
        updated: Credential | None = None
        for idx, cred in enumerate(credentials):
            if cred.id == cred_id:
                credentials[idx] = Credential(
                    id=cred.id,
                    username=cred.username,
                    secret=cred.secret,
                    cred_type=cred.cred_type,
                    domain=cred.domain,
                    status=status,
                    source=cred.source,
                )
                updated = credentials[idx]
                break
        if updated is None:
            return None
        self.save_all(credentials)
        return updated

    def verify(self, cred_id: str) -> Credential | None:
        """Placeholder verification — real LDAP/SMB checks land in Phase 7."""
        cred = next((c for c in self.list() if c.id == cred_id), None)
        if cred is None:
            return None
        if not cred.secret:
            return self.mark_status(cred_id, CredentialStatus.INVALID)
        return self.mark_status(cred_id, CredentialStatus.UNVERIFIED)
