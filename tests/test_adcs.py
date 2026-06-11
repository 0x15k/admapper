from pathlib import Path
from unittest.mock import MagicMock, patch

from admapper.adcs.analyze import run_adcs_analysis
from admapper.adcs.constants import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    EDITF_ATTRIBUTESUBJECTALTNAME2,
    EKU_ANY_PURPOSE,
    EKU_CERT_REQUEST_AGENT,
    EKU_CLIENT_AUTH,
)
from admapper.adcs.detect import detect_esc_vulnerabilities
from admapper.adcs.enum import AdcsEnumResult
from admapper.core.config import GlobalConfig
from admapper.core.credentials import CredentialStore
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.adcs import CertificateTemplateRecord, EnrollmentServiceRecord
from admapper.models.credential import CredentialStatus
from admapper.models.host import HostRecord


def test_detect_esc1_and_esc8() -> None:
    templates = [
        CertificateTemplateRecord(
            name="VulnUser",
            enrollment_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            extended_key_usage=[EKU_CLIENT_AUTH],
            low_priv_enrollment=True,
            enrollee_supplies_subject=True,
        ),
        CertificateTemplateRecord(
            name="AnyPurpose",
            enrollment_flags=0,
            extended_key_usage=[EKU_ANY_PURPOSE],
            low_priv_enrollment=True,
        ),
    ]
    services = [
        EnrollmentServiceRecord(
            name="corp-DC01-CA",
            dns_host="dc01.corp.local",
            web_enrollment=True,
            templates=["VulnUser", "AnyPurpose"],
        )
    ]
    findings = detect_esc_vulnerabilities(templates=templates, enrollment_services=services)
    escs = {f.esc for f in findings}
    assert "esc1" in escs
    assert "esc2" in escs
    assert "esc8" in escs
    assert "golden_cert" in escs


def test_detect_esc3_and_esc6() -> None:
    templates = [
        CertificateTemplateRecord(
            name="EnrollmentAgent",
            extended_key_usage=[EKU_CERT_REQUEST_AGENT],
            low_priv_enrollment=True,
        ),
        CertificateTemplateRecord(
            name="UserAuth",
            extended_key_usage=[EKU_CLIENT_AUTH],
            low_priv_enrollment=True,
        ),
    ]
    services = [
        EnrollmentServiceRecord(
            name="corp-CA",
            enrollment_flags=EDITF_ATTRIBUTESUBJECTALTNAME2,
            templates=["EnrollmentAgent", "UserAuth"],
        )
    ]
    findings = detect_esc_vulnerabilities(templates=templates, enrollment_services=services)
    escs = {f.esc for f in findings}
    assert "esc3" in escs
    assert "esc6" in escs


def test_run_adcs_analysis_writes_artifacts(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[389], is_domain_controller=True)]
    )
    store = CredentialStore(manager, "lab")
    cred = store.add("jsmith", "Secret123!", domain="corp.local")
    store.mark_status(cred.id, CredentialStatus.VALID)

    enum_result = AdcsEnumResult(
        enrollment_services=[
            EnrollmentServiceRecord(name="corp-CA", dns_host="dc01.corp.local", web_enrollment=True)
        ],
        templates=[
            CertificateTemplateRecord(
                name="VulnUser",
                enrollment_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                extended_key_usage=[EKU_CLIENT_AUTH],
                low_priv_enrollment=True,
                enrollee_supplies_subject=True,
            )
        ],
    )

    mock_ldap = MagicMock()
    with (
        patch("admapper.adcs.analyze.open_ldap_session", return_value=(mock_ldap, None)),
        patch("admapper.adcs.analyze.enumerate_adcs", return_value=enum_result),
        patch("admapper.adcs.analyze.print_manual_guide"),
    ):
        result = run_adcs_analysis(session)

    assert result.findings
    assert (tmp_path / "ws" / "lab" / "adcs_findings.json").is_file()
    assert (tmp_path / "ws" / "lab" / "adcs_inventory.json").is_file()
