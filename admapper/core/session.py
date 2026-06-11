from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from admapper.core.config import GlobalConfig, load_config, save_config
from admapper.core.credentials import CredentialStore
from admapper.core.paths import resolve_workspaces_root
from admapper.core.workspace import WorkspaceManager
from admapper.models.workspace import OperationMode, WorkspaceState


@dataclass
class Session:
    """Runtime context for the interactive shell."""

    config: GlobalConfig
    workspaces: WorkspaceManager
    workspace: WorkspaceState | None = None
    _dirty: bool = field(default=False, repr=False)

    @classmethod
    def bootstrap(cls, workspaces_root: Path | None = None) -> Session:
        config = load_config()
        root = resolve_workspaces_root(
            cli_override=workspaces_root,
            config_root=config.workspaces_root,
        )
        manager = WorkspaceManager(root)
        session = cls(config=config, workspaces=manager)
        if config.active_workspace and manager.exists(config.active_workspace):
            session.workspace = manager.load(config.active_workspace)
        return session

    def set_workspaces_root(self, path: str) -> Path:
        """Persist engagement output directory (console: ``set workspaces <path>``)."""
        root = resolve_workspaces_root(cli_override=path)
        self.config.workspaces_root = str(root)
        save_config(self.config)
        self.workspaces = WorkspaceManager(root)
        if self.config.active_workspace and self.workspaces.exists(self.config.active_workspace):
            self.workspace = self.workspaces.load(self.config.active_workspace)
        else:
            self.workspace = None
        return root

    @property
    def mode(self) -> OperationMode:
        if self.workspace is not None:
            return self.workspace.mode
        return self.config.default_mode

    @property
    def credentials(self) -> CredentialStore | None:
        if self.workspace is None:
            return None
        return CredentialStore(self.workspaces, self.workspace.name)

    def select_workspace(self, name: str, *, create: bool = True) -> WorkspaceState:
        if create:
            state = self.workspaces.get_or_create(name, mode=self.config.default_mode)
        else:
            state = self.workspaces.load(name)
        self.workspace = state
        self.config.active_workspace = state.name
        save_config(self.config)
        return state

    def persist_workspace(self) -> None:
        if self.workspace is None:
            return
        self.workspaces.save(self.workspace)

    def set_domain(self, domain: str) -> None:
        if self.workspace is None:
            raise RuntimeError("no active workspace — run: set workspace <name>")
        self.workspace.domain = domain.strip().lower()
        self.persist_workspace()

    def set_hosts(self, hosts: str) -> None:
        if self.workspace is None:
            raise RuntimeError("no active workspace — run: set workspace <name>")
        self.workspace.hosts = hosts.strip()
        self.persist_workspace()

    def set_mode(self, mode: OperationMode) -> None:
        if self.workspace is None:
            raise RuntimeError("no active workspace — run: set workspace <name>")
        self.workspace.mode = mode
        self.persist_workspace()

    def prompt_label(self) -> str:
        if self.workspace is None:
            return "admapper"
        parts = [self.workspace.name]
        if self.workspace.domain:
            parts.append(self.workspace.domain)
        return ":".join(parts)
