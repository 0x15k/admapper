from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.enumeration.ldap_users import LdapUserEnumResult
from admapper.enumeration.samr import SamrEnumResult
from admapper.enumeration.scan import run_user_enumeration
from admapper.models.host import HostRecord
from admapper.models.user import UserRecord, apply_uac_flags

UAC_DONT_REQ_PREAUTH = 0x400000


def _session_with_dc(tmp_path: Path) -> Session:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    hosts_store = HostsStore(manager, "lab")
    hosts_store.merge(
        [
            HostRecord(
                address="10.0.0.1",
                open_ports=[88, 389, 445],
                is_domain_controller=True,
            )
        ]
    )
    return session


def test_run_user_enumeration_merges_ldap_users(tmp_path: Path) -> None:
    session = _session_with_dc(tmp_path)
    ldap_users = [
        apply_uac_flags(
            UserRecord(
                username="alice",
                sources=["ldap"],
                uac=UAC_DONT_REQ_PREAUTH,
            )
        )
    ]
    ldap_result = LdapUserEnumResult(host="10.0.0.1", base_dn="DC=target,DC=example", users=ldap_users)

    with (
        patch("admapper.enumeration.scan.enumerate_users_ldap", return_value=ldap_result),
        patch("admapper.enumeration.scan.enumerate_users_samr") as samr_mock,
        patch("admapper.enumeration.scan.print_manual_guides_for_keys"),
    ):
        samr_mock.return_value = SamrEnumResult(host="10.0.0.1", users=[])
        result = run_user_enumeration(session)

    assert len(result.users) == 1
    assert result.users[0].asrep_roastable is True
    assert "asreproast" in result.guides_shown
    assert (tmp_path / "ws" / "lab" / "users.json").is_file()
