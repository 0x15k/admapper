import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.kerberos.analyze import run_kerberos_analysis


def _write_inventory(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_run_kerberos_analysis_delegations_and_backup_ops(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.workspace.owned_users = ["backupuser"]
    session.persist_workspace()

    inv = {
        "delegations": [
            {
                "object_name": "DC01",
                "object_type": "computer",
                "delegation_type": "unconstrained",
                "dn": "CN=DC01,OU=Computers,DC=target,DC=example",
            },
            {
                "object_name": "WEB01$",
                "object_type": "computer",
                "delegation_type": "constrained_pt",
                "targets": ["cifs/dc01.target.example"],
                "dn": "CN=WEB01,OU=Computers,DC=target,DC=example",
            },
        ],
        "groups": [
            {
                "name": "Backup Operators",
                "dn": "CN=Backup Operators,CN=Builtin,DC=target,DC=example",
                "members": ["CN=backupuser,CN=Users,DC=target,DC=example"],
            }
        ],
        "computers": [
            {
                "name": "WS01",
                "dn": "CN=WS01,OU=Computers,DC=target,DC=example",
                "dns_host": "ws01.target.example",
            }
        ],
    }
    _write_inventory(tmp_path / "ws" / "lab" / "auth_inventory.json", inv)

    acl_payload = {
        "findings": [
            {
                "principal": "backupuser",
                "right": "genericwrite",
                "target_name": "svcadmin",
                "target_type": "user",
            }
        ]
    }
    (tmp_path / "ws" / "lab" / "acl_findings.json").write_text(
        json.dumps(acl_payload),
        encoding="utf-8",
    )

    with patch("admapper.kerberos.analyze.print_manual_guide"):
        result = run_kerberos_analysis(session)

    techniques = {o.technique for o in result.opportunities}
    assert "unconstrained_delegation" in techniques
    assert "constrained_pt" in techniques
    assert "backup_operators" in techniques
    assert "shadow_credentials" in techniques
    assert "timeroast" in techniques

    owned = [o for o in result.opportunities if o.owned_relevant]
    assert any(o.technique == "backup_operators" for o in owned)
    assert any(o.technique == "shadow_credentials" for o in owned)

    assert (tmp_path / "ws" / "lab" / "kerberos_ops.json").is_file()


def test_constrained_pt_delegation_type_in_ldap_enum() -> None:
    from unittest.mock import MagicMock

    from admapper.auth.ldap_enum import (
        UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
        LdapAuthEnumResult,
        _collect_delegation_user,
    )

    entry = MagicMock()
    entry.userAccountControl.value = UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
    entry.distinguishedName.value = "CN=WEB01,DC=target,DC=example"
    allowed = MagicMock()
    allowed.values = ["cifs/dc.target.example"]
    setattr(entry, "msDS-AllowedToDelegateTo", allowed)
    entry.msDS_AllowedToActOnBehalfOfOtherIdentity = None

    result = LdapAuthEnumResult()
    _collect_delegation_user(entry, "WEB01$", "computer", result)
    dtypes = [d.delegation_type for d in result.delegations]
    assert "constrained_pt" in dtypes
