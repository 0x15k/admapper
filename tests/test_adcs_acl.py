from admapper.acl.enum import PrincipalContext
from admapper.adcs.acl_detect import detect_owned_adcs_abuse
from admapper.models.adcs import CertificateTemplateRecord, EnrollmentServiceRecord


def test_detect_template_enrollment_for_owned_group() -> None:
    it_sid = "S-1-5-21-1-2-3-1105"
    templates = [
        CertificateTemplateRecord(
            name="TargetSrv",
            low_priv_enrollment=False,
            security_aces=[
                {"trustee_sid": it_sid, "rights": ["enroll"]},
            ],
        )
    ]
    principals = [
        PrincipalContext(
            username="target.admin",
            user_dn="CN=target.admin,DC=target,DC=example",
            user_sid="S-1-5-21-1-2-3-2100",
            group_sids={it_sid: "IT"},
            sid_to_name={it_sid: "IT", "S-1-5-21-1-2-3-2100": "target.admin"},
        )
    ]
    findings = detect_owned_adcs_abuse(
        templates=templates,
        enrollment_services=[EnrollmentServiceRecord(name="corp-CA")],
        principals=principals,
        domain="target.example",
        dc_ip="10.0.0.1",
    )
    escs = {f.esc for f in findings}
    assert "template_enrollment" in escs
    assert any(f.template == "TargetSrv" for f in findings)


def test_detect_esc4_template_write() -> None:
    user_sid = "S-1-5-21-1-2-3-2100"
    templates = [
        CertificateTemplateRecord(
            name="VulnTemplate",
            security_aces=[{"trustee_sid": user_sid, "rights": ["genericwrite"]}],
        )
    ]
    principals = [
        PrincipalContext(
            username="operator",
            user_dn="CN=op,DC=target,DC=example",
            user_sid=user_sid,
            sid_to_name={user_sid: "operator"},
        )
    ]
    findings = detect_owned_adcs_abuse(
        templates=templates,
        enrollment_services=[],
        principals=principals,
    )
    assert any(f.esc == "esc4" for f in findings)
