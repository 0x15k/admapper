from pathlib import Path

from admapper.core.credentials import CredentialStore
from admapper.core.workspace import WorkspaceManager
from admapper.models.credential import CredentialStatus, CredentialType


def test_add_list_remove_credentials(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path)
    manager.create("lab")
    store = CredentialStore(manager, "lab")

    cred = store.add("alice", "Secret123!", domain="corp.local", cred_type=CredentialType.PASSWORD)
    assert cred.username == "alice"
    assert len(store.list()) == 1

    updated = store.mark_status(cred.id, CredentialStatus.VALID)
    assert updated is not None
    assert updated.status == CredentialStatus.VALID

    assert store.remove(cred.id) is True
    assert store.list() == []


def test_verify_marks_unverified_when_secret_present(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path)
    manager.create("lab")
    store = CredentialStore(manager, "lab")
    cred = store.add("bob", "x", domain="corp.local")
    verified = store.verify(cred.id)
    assert verified is not None
    assert verified.status == CredentialStatus.UNVERIFIED
