from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.credentials import CredentialStore
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.creds.auth_checks import AuthCheckResult, verify_credential_checks
from admapper.creds.verify import run_credential_verify
from admapper.models.credential import CredentialStatus
from admapper.models.host import HostRecord


def test_verify_credential_checks_valid_when_ldap_succeeds(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    manager.create("lab")
    store = CredentialStore(manager, "lab")
    cred = store.add("jsmith", "Secret123!", domain="corp.local")

    with patch(
        "admapper.creds.auth_checks.check_ldap",
        return_value=True,
    ), patch(
        "admapper.creds.auth_checks.check_smb",
        return_value=False,
    ), patch(
        "admapper.creds.auth_checks.check_kerberos_tgt",
        return_value=False,
    ):
        result = verify_credential_checks(cred, "10.0.0.1", "corp.local")

    assert result.is_valid is True
    assert result.ldap is True


def test_run_credential_verify_marks_valid(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    cred = session.credentials.add("jsmith", "Secret123!", domain="corp.local")

    with patch(
        "admapper.creds.verify.verify_credential_checks",
        return_value=AuthCheckResult(ldap=True, smb=True, kerberos=False),
    ):
        result = run_credential_verify(session, cred.id)

    assert result.status == CredentialStatus.VALID
    refreshed = session.credentials.list()[0]
    assert refreshed.status == CredentialStatus.VALID


def test_verify_credential_checks_protected_users_kerberos_only(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    manager.create("lab")
    store = CredentialStore(manager, "lab")
    cred = store.add("svc_recovery", "Em3rg3ncyPa$$2026", domain="logging.htb")

    with patch(
        "admapper.creds.auth_checks.check_ldap",
    ) as mock_ldap, patch(
        "admapper.creds.auth_checks.check_smb",
    ) as mock_smb, patch(
        "admapper.creds.auth_checks.check_kerberos_tgt",
        return_value=True,
    ) as mock_krb:
        result = verify_credential_checks(
            cred,
            "10.129.20.182",
            "logging.htb",
            protected_users={"svc_recovery"},
            ws_path=str(manager.path_for("lab")),
        )

    assert result.is_valid_kerberos_only() is True
    mock_ldap.assert_not_called()
    mock_smb.assert_not_called()
    mock_krb.assert_called_once()
    assert mock_krb.call_args.kwargs.get("kerberos_only") is True


def test_run_credential_verify_marks_invalid(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    cred = session.credentials.add("baduser", "nope", domain="corp.local")

    with patch(
        "admapper.creds.verify.verify_credential_checks",
        return_value=AuthCheckResult(ldap=False, smb=False, kerberos=False),
    ):
        result = run_credential_verify(session, cred.id)

    assert result.status == CredentialStatus.INVALID
