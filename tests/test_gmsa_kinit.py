import sys
from unittest.mock import MagicMock, patch

from admapper.exploit.acl_exploit import _pick_exploit_credential
from admapper.exploit.gmsa import _modify_gmsa_membership_gssapi
from admapper.winrm.tickets import mit_kinit_tgt


def test_mit_kinit_tgt_stops_after_tgt(tmp_path) -> None:
    ccache = tmp_path / "test.ccache"
    krb5_conf = tmp_path / "krb5.conf"
    with patch("admapper.winrm.tickets._mit_kinit_env") as mock_env:
        mock_env.return_value = {"KRB5CCNAME": "FILE:test"}
        mit_kinit_tgt(
            username="svc_sql",
            password="secret",
            domain="corp.local",
            dc_ip="10.0.0.1",
            ccache=ccache,
            krb5_conf=krb5_conf,
        )
        mock_env.assert_called_once()


def test_pick_exploit_credential_prefers_verified_candidate(tmp_path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "password_candidates.json").write_text(
        '{"candidates": [{"username": "svc_sql", "password": "WelcomePassword123!", "verified": true}]}',
        encoding="utf-8",
    )

    session = MagicMock()
    session.workspace.name = "ws"
    session.workspaces.path_for.return_value = ws
    session.workspace.domain = "corp.local"
    from admapper.models.credential import Credential, CredentialStatus, CredentialType

    session.credentials.list.return_value = [
        Credential(
            username="svc_sql",
            secret="WelcomePassword123!",
            status=CredentialStatus.VALID,
            cred_type=CredentialType.PASSWORD,
            source="share_loot",
        )
    ]

    cred = _pick_exploit_credential(session, "svc_sql")
    assert cred is not None
    assert cred.secret == "WelcomePassword123!"


def test_gssapi_modify_uses_faketime_subprocess_when_skew_set(tmp_path) -> None:
    krb5_conf = tmp_path / "krb5.conf"
    ccache = tmp_path / "test.ccache"
    krb5_conf.write_text("[libdefaults]\n", encoding="utf-8")
    ccache.write_text("", encoding="utf-8")

    with (
        patch("admapper.core.platform.resolve_faketime", return_value="/usr/bin/faketime"),
        patch("admapper.exploit.gmsa.run_command") as mock_run,
    ):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"ok": true, "err": null}\n',
            stderr="",
        )
        ok, err = _modify_gmsa_membership_gssapi(
            ldap_host="dc01.corp.local",
            gmsa_dn="CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb",
            principal_sid="S-1-5-21-1-2-3-1000",
            krb5_conf=krb5_conf,
            ccache=ccache,
            clock_skew="+7h",
        )
    assert ok is True
    assert err is None
    mock_run.assert_called_once()
    assert mock_run.call_args.kwargs.get("use_clock_skew") is True
    assert mock_run.call_args.kwargs.get("clock_skew") == "+7h"
    assert mock_run.call_args[0][0][0] == sys.executable
