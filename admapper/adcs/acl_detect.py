from __future__ import annotations

from admapper.acl.enum import PrincipalContext
from admapper.adcs.catalog import esc_meta
from admapper.adcs.certipy import build_certipy_commands
from admapper.adcs.eku import classify_template_eku
from admapper.adcs.template_sd import ace_has_enroll, ace_has_template_write
from admapper.models.adcs import AdcsFinding, CertificateTemplateRecord, EnrollmentServiceRecord


def _principal_label(principal: PrincipalContext, sid: str) -> str:
    return principal.sid_to_name.get(sid, sid)


def _principal_for_sid(principal: PrincipalContext, sid: str) -> str:
    if sid == principal.user_sid:
        return principal.username
    return principal.group_sids.get(sid, _principal_label(principal, sid))


def _finding(
    esc: str,
    *,
    template: str | None = None,
    ca_name: str | None = None,
    detail: str = "",
    principal: str | None = None,
    domain: str = "",
    dc_ip: str = "",
    extra_commands: tuple[str, ...] = (),
    template_record: CertificateTemplateRecord | None = None,
) -> AdcsFinding:
    meta = esc_meta(esc)
    commands = list(meta.manual_commands)
    eku_profile = classify_template_eku(
        template_record.extended_key_usage if template_record else None
    )
    cert_auth_viable = eku_profile.get("cert_auth_viable", True)
    wsus_chain_step = bool(eku_profile.get("wsus_chain_step"))
    eku_labels = eku_profile.get("eku_labels") or []

    if (
        domain
        and dc_ip
        and principal
        and template
        and esc in ("esc4", "template_enrollment", "esc1")
    ):
        commands = build_certipy_commands(
            esc=esc,
            domain=domain,
            dc_ip=dc_ip,
            principal=principal,
            template=template,
            ca_name=ca_name or "",
            cert_auth_viable=cert_auth_viable,
            wsus_chain_step=wsus_chain_step,
        )
    commands.extend(extra_commands)

    summary = meta.summary
    title = meta.title
    if esc == "template_enrollment" and wsus_chain_step:
        title = f"{template} enrollment → WSUS chain (Server Auth only)"
        summary = (
            f"{principal} can enroll in {template} (EKU: {', '.join(eku_labels) or 'unknown'}). "
            "No Client Authentication — cert cannot be used for PKINIT/login; use with WSUS spoofing toward DA."
        )
        if not detail:
            detail = summary

    return AdcsFinding(
        esc=esc,
        title=title,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        template=template,
        ca_name=ca_name,
        summary=summary,
        detail=detail,
        manual_commands=commands,
        principal=principal,
        prerequisites_met=principal is not None,
        cert_auth_viable=cert_auth_viable if template_record else None,
        wsus_chain_step=wsus_chain_step if template_record else None,
        eku_summary=", ".join(eku_labels),
    )


def detect_owned_adcs_abuse(
    *,
    templates: list[CertificateTemplateRecord],
    enrollment_services: list[EnrollmentServiceRecord],
    principals: list[PrincipalContext],
    domain: str = "",
    dc_ip: str = "",
    group_enroll_hints: dict[str, list[str]] | None = None,
) -> list[AdcsFinding]:
    """Detect ESC4/ESC7/template enrollment for owned principals (not just low-priv)."""
    if not principals:
        return []

    findings: list[AdcsFinding] = []
    default_ca = enrollment_services[0].name if enrollment_services else None
    principal_sids: dict[str, PrincipalContext] = {}
    for principal in principals:
        for sid in principal.all_sids:
            principal_sids[sid] = principal

    for template in templates:
        for ace_dict in template.security_aces or []:
            sid = str(ace_dict.get("trustee_sid") or "")
            rights = list(ace_dict.get("rights") or [])
            principal = principal_sids.get(sid)
            if principal is None:
                continue
            label = _principal_for_sid(principal, sid)
            from admapper.adcs.template_sd import TemplateAce

            ace = TemplateAce(trustee_sid=sid, rights=rights)

            if ace_has_template_write(ace):
                findings.append(
                    _finding(
                        "esc4",
                        template=template.name,
                        ca_name=default_ca,
                        principal=principal.username,
                        detail=f"{label} has {', '.join(rights)} on template {template.name}",
                        domain=domain,
                        dc_ip=dc_ip,
                        extra_commands=(
                            f"certipy template -u {principal.username}@{domain} -hashes :<NTLM> "
                            f"-template {template.name} -save-old",
                            f"certipy template -u {principal.username}@{domain} -hashes :<NTLM> "
                            f"-template {template.name} -add-client-auth",
                        ),
                    )
                )

            if ace_has_enroll(ace) and not template.low_priv_enrollment:
                findings.append(
                    _finding(
                        "template_enrollment",
                        template=template.name,
                        ca_name=default_ca,
                        principal=principal.username,
                        detail=f"{label} can enroll in restricted template {template.name}",
                        domain=domain,
                        dc_ip=dc_ip,
                        template_record=template,
                    )
                )

    # Fallback: auth_inventory group → template name hints (when SD enroll ACE not visible)
    hints = group_enroll_hints or {}
    template_by_name = {t.name: t for t in templates}
    for principal in principals:
        for template_name in hints.get(principal.username, []):
            if any(
                f.esc == "template_enrollment"
                and f.template == template_name
                and f.principal == principal.username
                for f in findings
            ):
                continue
            findings.append(
                _finding(
                    "template_enrollment",
                    template=template_name,
                    ca_name=default_ca,
                    principal=principal.username,
                    detail=f"group membership suggests enrollment in {template_name}",
                    domain=domain,
                    dc_ip=dc_ip,
                    template_record=template_by_name.get(template_name),
                )
            )

    for service in enrollment_services:
        for ace_dict in service.security_aces or []:
            sid = str(ace_dict.get("trustee_sid") or "")
            rights = list(ace_dict.get("rights") or [])
            principal = principal_sids.get(sid)
            if principal is None:
                continue
            if not any(r in rights for r in ("manage_ca", "manage_certificates", "genericall")):
                continue
            label = _principal_for_sid(principal, sid)
            findings.append(
                _finding(
                    "esc7",
                    ca_name=service.name,
                    principal=principal.username,
                    detail=f"{label} has CA management rights on {service.name}: {', '.join(rights)}",
                    domain=domain,
                    dc_ip=dc_ip,
                )
            )

    seen: set[tuple[str, str | None, str | None, str | None]] = set()
    unique: list[AdcsFinding] = []
    for item in findings:
        key = (item.esc, item.template, item.ca_name, item.principal)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
