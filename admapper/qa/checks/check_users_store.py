from pathlib import Path

from admapper.core.users import UsersStore
from admapper.core.workspace import WorkspaceManager
from admapper.models.user import UserRecord, apply_uac_flags

UAC_DONT_REQ_PREAUTH = 0x400000


def test_users_merge_combines_sources(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path)
    manager.create("lab")
    store = UsersStore(manager, "lab")
    store.merge([UserRecord(username="alice", sources=["ldap"])])
    merged = store.merge([UserRecord(username="alice", sources=["samr"], rid=1103)])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"ldap", "samr"}
    assert merged[0].rid == 1103


def test_apply_uac_flags_asrep() -> None:
    user = apply_uac_flags(UserRecord(username="svc", uac=UAC_DONT_REQ_PREAUTH))
    assert user.asrep_roastable is True
