import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from admapper.auth.auth_enum import run_auth_enumeration
from admapper.auth.ldap_enum import LdapAuthEnumResult
from admapper.auth.ldap_session import LdapSession
from admapper.auth.smb_enum import SmbAuthEnumResult
from admapper.core.config import GlobalConfig
from admapper.core.credentials import CredentialStore
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.ad_object import GroupRecord
from admapper.models.credential import CredentialStatus
from admapper.models.host import HostRecord
from admapper.creds.policy import LockoutUserState, PolicyFetchResult
from admapper.models.spray import DomainLockoutPolicy
from admapper.models.user import UserRecord


def test_run_auth_enumeration_saves_inventory(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    store = CredentialStore(manager, "lab")
    cred = store.add("jsmith", "Secret123!", domain="corp.local")
    store.mark_status(cred.id, CredentialStatus.VALID)

    ldap_result = LdapAuthEnumResult(
        users=[UserRecord(username="jsmith", sources=["ldap_auth"])],
        groups=[GroupRecord(name="Domain Users", dn="CN=Domain Users,DC=corp,DC=local")],
    )
    smb_result = SmbAuthEnumResult(shares=["SYSVOL", "NETLOGON"])

    mock_conn = MagicMock()
    mock_session = LdapSession(host="10.0.0.1", base_dn="DC=corp,DC=local", conn=mock_conn)

    lockout_ctx = PolicyFetchResult(
        host="10.0.0.1",
        base_dn="DC=corp,DC=local",
        policy=DomainLockoutPolicy(lockout_threshold=5, source_host="10.0.0.1"),
        user_states=[LockoutUserState(username="jsmith", bad_pwd_count=1)],
    )

    with (
        patch("admapper.auth.auth_enum.open_ldap_session", return_value=(mock_session, None)),
        patch("admapper.auth.auth_enum.enumerate_ldap_authenticated", return_value=ldap_result),
        patch("admapper.auth.auth_enum.enumerate_smb_authenticated", return_value=smb_result),
        patch("admapper.auth.auth_enum.fetch_lockout_context", return_value=lockout_ctx),
        patch("admapper.auth.auth_enum.print_manual_guide"),
    ):
        result = run_auth_enumeration(session, cred, "10.0.0.1", "corp.local")

    assert result.inventory_path is not None
    ws_lab = tmp_path / "ws" / "lab"
    assert (ws_lab / "auth_inventory.json").is_file()
    assert (ws_lab / "lockout_policy.json").is_file()
    assert (ws_lab / "bloodhound" / "users.json").is_file()
    assert (ws_lab / "graph.json").is_file()
    inv = json.loads((ws_lab / "auth_inventory.json").read_text(encoding="utf-8"))
    user = inv["users"][0]
    assert user["bad_pwd_count"] == 1
