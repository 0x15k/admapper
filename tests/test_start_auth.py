from pathlib import Path
from unittest.mock import patch

from admapper.auth.auth_enum import AuthEnumResult
from admapper.auth.ldap_context import AuthenticatedUserContext
from admapper.auth.start_auth import run_start_auth
from admapper.core.config import GlobalConfig
from admapper.core.credentials import CredentialStore
from admapper.core.graph import GraphStore
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.creds.verify import CredentialVerifyResult
from admapper.models.credential import CredentialStatus
from admapper.models.host import HostRecord


def test_run_start_auth_marks_owned_and_graph(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    store = CredentialStore(manager, "lab")
    cred = store.add("jsmith", "Secret123!", domain="target.example")
    store.mark_status(cred.id, CredentialStatus.VALID)

    with (
        patch("admapper.auth.start_auth.confirm", return_value=True),
        patch(
            "admapper.auth.start_auth.fetch_authenticated_user_context",
            return_value=AuthenticatedUserContext(
                username="jsmith",
                domain="target.example",
                member_of=["CN=Staff,DC=target,DC=example"],
            ),
        ),
        patch(
            "admapper.auth.start_auth.run_auth_enumeration",
            return_value=AuthEnumResult(
                inventory_path="auth_inventory.json",
                bloodhound_dir="bloodhound",
            ),
        ),
    ):
        result = run_start_auth(session, cred_id=cred.id)

    assert result.owned_user == "jsmith"
    assert result.inventory_path == "auth_inventory.json"
    assert "jsmith" in session.workspace.owned_users

    graph = GraphStore(manager, "lab").load()
    owned_nodes = [n for n in graph["nodes"] if n.get("owned")]
    assert any(n.get("username") == "jsmith" for n in owned_nodes)
    assert (tmp_path / "ws" / "lab" / "auth_scan.json").is_file()


def test_run_start_auth_verifies_unverified_cred(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    cred = session.credentials.add("jsmith", "Secret123!", domain="target.example")
    valid_cred = session.credentials.mark_status(cred.id, CredentialStatus.VALID)
    assert valid_cred is not None

    with (
        patch("admapper.auth.start_auth.confirm", return_value=True),
        patch(
            "admapper.auth.start_auth.run_credential_verify",
            return_value=CredentialVerifyResult(
                credential=valid_cred,
                checks={"ldap": True},
                status=CredentialStatus.VALID,
            ),
        ),
        patch(
            "admapper.auth.start_auth.fetch_authenticated_user_context",
            return_value=AuthenticatedUserContext(username="jsmith", domain="target.example"),
        ),
        patch(
            "admapper.auth.start_auth.run_auth_enumeration",
            return_value=AuthEnumResult(),
        ),
    ):
        session.credentials.mark_status(cred.id, CredentialStatus.UNVERIFIED)
        result = run_start_auth(session, cred_id=cred.id)

    assert result.credential.status == CredentialStatus.VALID
