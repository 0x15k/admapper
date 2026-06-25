from __future__ import annotations

from admapper.adcs.catalog import esc_meta
from admapper.adcs.constants import (
    AUTH_EKUS,
    CT_FLAG_NO_SECURITY_EXTENSION,
    EDITF_ATTRIBUTESUBJECTALTNAME2,
    EKU_ANY_PURPOSE,
    EKU_CERT_REQUEST_AGENT,
    IF_ENFORCEENCRYPTICERTREQUEST,
)
from admapper.models.adcs import AdcsFinding, CertificateTemplateRecord, EnrollmentServiceRecord


def _finding(
    esc: str,
    *,
    template: str | None = None,
    ca_name: str | None = None,
    detail: str = "",
) -> AdcsFinding:
    meta = esc_meta(esc)
    return AdcsFinding(
        esc=esc,
        title=meta.title,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        template=template,
        ca_name=ca_name,
        summary=meta.summary,
        detail=detail,
        manual_commands=list(meta.manual_commands),
    )


def _has_auth_eku(template: CertificateTemplateRecord) -> bool:
    if not template.extended_key_usage:
        return True
    return any(eku in AUTH_EKUS for eku in template.extended_key_usage)


def _can_enroll_low_priv(template: CertificateTemplateRecord) -> bool:
    return template.low_priv_enrollment


def detect_esc_vulnerabilities(
    *,
    templates: list[CertificateTemplateRecord],
    enrollment_services: list[EnrollmentServiceRecord],
) -> list[AdcsFinding]:
    """Phase 12.1–12.4 — map templates/CAs to ESC findings."""
    findings: list[AdcsFinding] = []
    ca_names = [s.name for s in enrollment_services]
    default_ca = ca_names[0] if ca_names else None

    agent_templates: list[str] = []
    auth_templates: list[str] = []

    for template in templates:
        name = template.name
        if not _can_enroll_low_priv(template):
            continue

        ekus = set(template.extended_key_usage)

        # ESC1
        if (
            template.enrollee_supplies_subject
            and not template.requires_manager_approval
            and _has_auth_eku(template)
        ):
            findings.append(
                _finding(
                    "esc1",
                    template=name,
                    ca_name=default_ca,
                    detail="ENROLLEE_SUPPLIES_SUBJECT + client auth EKU + enrollment",
                )
            )

        # ESC2 — Any Purpose or empty EKU with enrollment
        if EKU_ANY_PURPOSE in ekus or not template.extended_key_usage:
            findings.append(
                _finding(
                    "esc2",
                    template=name,
                    ca_name=default_ca,
                    detail="Any Purpose or no EKU restriction",
                )
            )

        # ESC3 agent tracking
        if EKU_CERT_REQUEST_AGENT in ekus:
            agent_templates.append(name)
        if _has_auth_eku(template) and EKU_CERT_REQUEST_AGENT not in ekus:
            auth_templates.append(name)

        # ESC15 — schema v2 + application policy
        if (template.schema_version or 0) >= 2:
            findings.append(
                _finding(
                    "esc15",
                    template=name,
                    ca_name=default_ca,
                    detail=f"schema version {template.schema_version}",
                )
            )

        # ESC9 — CT_FLAG_NO_SECURITY_EXTENSION + auth EKU
        enrollment_flags = getattr(template, "enrollment_flags", 0) or 0
        if (
            enrollment_flags & CT_FLAG_NO_SECURITY_EXTENSION
            and _has_auth_eku(template)
        ):
            findings.append(
                _finding(
                    "esc9",
                    template=name,
                    ca_name=default_ca,
                    detail="CT_FLAG_NO_SECURITY_EXTENSION set + client auth EKU — "
                           "exploitable with GenericWrite + weak StrongCertificateBindingEnforcement",
                )
            )

        # ESC13 — issuance policy OID linked to group
        issuance_policies = getattr(template, "issuance_policies", None) or []
        if issuance_policies and _has_auth_eku(template):
            findings.append(
                _finding(
                    "esc13",
                    template=name,
                    ca_name=default_ca,
                    detail=f"issuance policy OID(s) present: {issuance_policies[:3]} — "
                           "check msDS-OIDToGroupLink for effective group membership",
                )
            )

    # ESC3 chain hint
    if agent_templates and auth_templates:
        findings.append(
            _finding(
                "esc3",
                template=agent_templates[0],
                ca_name=default_ca,
                detail=f"agent={agent_templates[0]}, victim candidates={auth_templates[:3]}",
            )
        )

    for service in enrollment_services:
        if service.web_enrollment:
            finding = _finding(
                "esc8",
                ca_name=service.name,
                detail=f"web enrollment @ {service.dns_host}",
            )
            finding.requires_external_listener = True
            findings.append(finding)
        flags = service.enrollment_flags or 0
        if flags & EDITF_ATTRIBUTESUBJECTALTNAME2:
            findings.append(
                _finding(
                    "esc6",
                    ca_name=service.name,
                    detail="CA policy EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                )
            )
        # ESC11 — RPC enrollment without encryption enforcement
        if not (flags & IF_ENFORCEENCRYPTICERTREQUEST):
            finding = _finding(
                "esc11",
                ca_name=service.name,
                detail=f"IF_ENFORCEENCRYPTICERTREQUEST not set on {service.dns_host} — "
                       "NTLM relay to MS-ICPR RPC interface possible",
            )
            finding.requires_external_listener = True
            findings.append(finding)

    # Golden cert intel — AD CS present with CA
    if enrollment_services:
        findings.append(
            _finding(
                "golden_cert",
                ca_name=default_ca,
                detail="Backup CA cert with certipy ca -backup for offline Golden Certificate",
            )
        )

    # Deduplicate
    seen: set[tuple[str, str | None, str | None]] = set()
    unique: list[AdcsFinding] = []
    for item in findings:
        key = (item.esc, item.template, item.ca_name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
