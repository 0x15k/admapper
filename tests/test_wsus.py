from admapper.wsus.analyze import build_wsus_opportunities
from admapper.wsus.prerequisites import check_wsus_prerequisites, owned_groups_for_user


def test_owned_groups_for_user() -> None:
    inventory = {
        "users": [{"username": "jaylee.doe", "dn": "CN=jaylee,DC=target,DC=example"}],
        "groups": [
            {
                "name": "IT",
                "members": ["CN=jaylee,DC=target,DC=example"],
            }
        ],
    }
    groups = owned_groups_for_user(inventory, "jaylee.doe")
    assert "IT" in groups


def test_wsus_prerequisites_require_adcs() -> None:
    checks = check_wsus_prerequisites(
        username="jaylee.doe",
        groups=["IT"],
        has_adcs=False,
        wsus_share=True,
        enroll_findings=[],
        acl_findings=[],
    )
    adcs_check = next(c for c in checks if c.key == "adcs_present")
    assert not adcs_check.met


def test_build_wsus_cert_chain_when_enrollment_finding() -> None:
    class FakeSession:
        workspace = type("W", (), {"owned_users": ["jaylee.doe"]})()

    session = FakeSession()
    adcs_findings = {
        "findings": [
            {
                "esc": "template_enrollment",
                "principal": "jaylee.doe",
                "template": "UpdateSrv",
                "ca_name": "corp-DC01-CA",
            }
        ]
    }
    inventory = {
        "users": [{"username": "jaylee.doe", "dn": "CN=jaylee,DC=target,DC=example"}],
        "groups": [{"name": "IT", "members": ["CN=jaylee,DC=target,DC=example"]}],
        "smb_shares": ["WSUSTemp"],
    }
    ops = build_wsus_opportunities(
        session,  # type: ignore[arg-type]
        inventory=inventory,
        adcs_inventory={"enrollment_services": [{"name": "corp-DC01-CA"}]},
        adcs_findings=adcs_findings,
        acl_data=None,
        dc_ip="192.168.10.130",
    )
    techniques = {o.technique for o in ops}
    assert "wsus_cert_chain" in techniques
