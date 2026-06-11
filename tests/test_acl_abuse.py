from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from admapper.acl.analyze import run_acl_analysis
from admapper.acl.enum import AclTarget, PrincipalContext
from admapper.acl.parse import parse_security_descriptor
from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.credential import CredentialStatus


def _empty_sd():
    from impacket.ldap import ldaptypes

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = b""
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


def _build_allowed_ace(trustee_sid: str, *, access_mask: int) -> object:
    from impacket.ldap import ldaptypes

    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = access_mask
    acedata["Sid"] = ldaptypes.LDAP_SID()
    acedata["Sid"].fromCanonical(trustee_sid)
    ace["Ace"] = acedata
    return ace


def _build_object_ace(trustee_sid: str, *, privguid: str, access_mask: int) -> object:
    from impacket.ldap import ldaptypes
    from impacket.uuid import string_to_bin

    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = access_mask
    acedata["ObjectType"] = string_to_bin(privguid)
    acedata["InheritedObjectType"] = b""
    acedata["Sid"] = ldaptypes.LDAP_SID()
    acedata["Sid"].fromCanonical(trustee_sid)
    acedata["Flags"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    ace["Ace"] = acedata
    return ace


def _build_genericall_ace(trustee_sid: str) -> bytes:
    from admapper.acl.rights import AD_GENERIC_ALL

    sd = _empty_sd()
    sd["Dacl"].aces.append(_build_allowed_ace(trustee_sid, access_mask=AD_GENERIC_ALL))
    return sd.getData()


def _build_force_change_password_ace(trustee_sid: str) -> bytes:
    from admapper.acl.rights import ADS_RIGHT_DS_CONTROL_ACCESS, GUID_FORCE_CHANGE_PASSWORD

    sd = _empty_sd()
    sd["Dacl"].aces.append(
        _build_object_ace(
            trustee_sid,
            privguid=GUID_FORCE_CHANGE_PASSWORD,
            access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
        )
    )
    return sd.getData()


@pytest.fixture
def trustee_sid() -> str:
    return "S-1-5-21-1320953649-1542204690-3067251696-1106"


def test_parse_genericall_ace(trustee_sid: str) -> None:
    raw = _build_genericall_ace(trustee_sid)
    parsed = parse_security_descriptor(raw, object_classes=["top", "group"])
    rights = {ace.trustee_sid: ace.rights for ace in parsed.aces}
    assert rights[trustee_sid] == ["genericall"]


def test_parse_force_change_password(trustee_sid: str) -> None:
    raw = _build_force_change_password_ace(trustee_sid)
    parsed = parse_security_descriptor(raw, object_classes=["top", "user"])
    assert any("forcechangepassword" in ace.rights for ace in parsed.aces)


def test_run_acl_analysis_writes_findings(tmp_path: Path, trustee_sid: str) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    session.workspace.owned_users = ["jsmith"]
    session.persist_workspace()

    from admapper.core.credentials import CredentialStore
    from admapper.core.hosts import HostsStore
    from admapper.models.host import HostRecord

    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[389], is_domain_controller=True)]
    )
    store = CredentialStore(manager, "lab")
    cred = store.add("jsmith", "Secret123!", domain="corp.local")
    store.mark_status(cred.id, CredentialStatus.VALID)

    import json

    inv = {
        "users": [
            {
                "username": "admin",
                "dn": "CN=Administrator,CN=Users,DC=corp,DC=local",
            }
        ],
        "groups": [
            {
                "name": "Domain Admins",
                "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
            }
        ],
        "computers": [],
    }
    (tmp_path / "ws" / "lab" / "auth_inventory.json").write_text(
        json.dumps(inv),
        encoding="utf-8",
    )

    principal = PrincipalContext(
        username="jsmith",
        user_dn="CN=John Smith,CN=Users,DC=corp,DC=local",
        user_sid=trustee_sid,
        sid_to_name={trustee_sid: "jsmith"},
    )
    targets = [
        AclTarget(
            dn="CN=Domain Admins,CN=Users,DC=corp,DC=local",
            name="Domain Admins",
            object_type="group",
            object_classes=["top", "group"],
        )
    ]
    sd_bytes = _build_genericall_ace(trustee_sid)

    mock_conn = MagicMock()
    mock_ldap = MagicMock()
    mock_ldap.conn = mock_conn

    with (
        patch("admapper.acl.analyze.open_ldap_session", return_value=(mock_ldap, None)),
        patch("admapper.acl.analyze.resolve_principal_context", return_value=principal),
        patch("admapper.acl.analyze.build_acl_targets", return_value=targets),
        patch("admapper.acl.analyze.fetch_security_descriptor", return_value=sd_bytes),
        patch("admapper.acl.analyze.print_manual_guide"),
    ):
        result = run_acl_analysis(session)

    assert result.findings
    assert result.findings[0].right == "genericall"
    assert (tmp_path / "ws" / "lab" / "acl_findings.json").is_file()
