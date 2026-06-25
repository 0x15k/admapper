from __future__ import annotations

import re
from dataclasses import dataclass, field

from ldap3 import LEVEL
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from admapper.adcs.constants import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_PEND_ALL_REQUESTS,
    LOW_PRIV_ENROLL_SIDS,
)
from admapper.adcs.template_sd import parse_ca_sd_from_entry, parse_template_sd_from_entry
from admapper.auth.ldap_session import LdapSession
from admapper.models.adcs import CertificateTemplateRecord, EnrollmentServiceRecord


@dataclass
class AdcsEnumResult:
    enrollment_services: list[EnrollmentServiceRecord] = field(default_factory=list)
    templates: list[CertificateTemplateRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _config_nc(session: LdapSession) -> str | None:
    info = session.conn.server.info
    if not info:
        return None
    values = info.other.get("configurationNamingContext")
    return values[0] if values else None


def _pki_base(config_nc: str) -> str:
    return f"CN=Public Key Services,CN=Services,{config_nc}"


def _attr_int(entry, name: str, default: int = 0) -> int:
    if not getattr(entry, name, None):
        return default
    try:
        return int(getattr(entry, name).value)
    except (TypeError, ValueError):
        return default


def _attr_str(entry, name: str) -> str | None:
    if not getattr(entry, name, None):
        return None
    return str(getattr(entry, name).value)


def _attr_list(entry, name: str) -> list[str]:
    if not getattr(entry, name, None):
        return []
    return [str(v) for v in getattr(entry, name).values]


def _low_priv_enrollment_from_sd(entry) -> bool:
    if not getattr(entry, "nTSecurityDescriptor", None):
        return False
    try:
        from impacket.ldap import ldaptypes
        from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE

        raw = entry.nTSecurityDescriptor.raw_values
        if not raw:
            return False
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(raw[0])
        dacl = sd["Dacl"]
        if dacl == b"" or not hasattr(dacl, "aces"):
            return False
        enroll_uuids = {
            "00000000-0000-0000-0000-000000000000",
            "0e10c968-78fb-11d2-90d4-00c04f79dc55",
            "a05b8cc2-17bc-4802-a710-e7c15ab866a2",
        }
        for ace in dacl.aces:
            if ace["AceType"] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                continue
            body = ace["Ace"]
            sid = body["Sid"].formatCanonical()
            if sid in LOW_PRIV_ENROLL_SIDS:
                return True
            flags = int(body.get("Flags", 0))
            if flags == 2 and hasattr(body, "InheritedObjectType"):
                from admapper.acl.parse import guid_le_to_str

                uuid = guid_le_to_str(body["InheritedObjectType"])
                if uuid in enroll_uuids:
                    return True
    except Exception:
        return False
    return False


def _web_enrollment_from_servers(raw: str | None) -> bool:
    if not raw:
        return False
    # ESC8 requires unencrypted HTTP web enrollment
    return "http://" in raw.lower()


def enumerate_adcs(session: LdapSession) -> AdcsEnumResult:
    """Phase 12.1 — LDAP enumeration of AD CS enrollment services and templates."""
    result = AdcsEnumResult()
    config_nc = _config_nc(session)
    if not config_nc:
        result.errors.append("configurationNamingContext not available")
        return result

    pki = _pki_base(config_nc)
    enroll_base = f"CN=Enrollment Services,{pki}"
    controls = security_descriptor_control(criticality=True, sdflags=0x04)

    try:
        session.conn.search(
            search_base=enroll_base,
            search_filter="(objectClass=pKIEnrollmentService)",
            search_scope=LEVEL,
            attributes=[
                "cn",
                "dNSHostName",
                "displayName",
                "certificateTemplates",
                "msPKI-Enrollment-Servers",
                "msPKI-Enrollment-Flag",
                "nTSecurityDescriptor",
            ],
            controls=controls,
        )
        offered: set[str] = set()
        for entry in session.conn.entries:
            name = _attr_str(entry, "cn") or ""
            templates = _attr_list(entry, "certificateTemplates")
            offered.update(templates)
            servers = _attr_str(entry, "msPKI-Enrollment-Servers")
            ca_aces = [
                {"trustee_sid": a.trustee_sid, "rights": list(a.rights)}
                for a in parse_ca_sd_from_entry(entry)
            ]
            result.enrollment_services.append(
                EnrollmentServiceRecord(
                    name=name,
                    dns_host=_attr_str(entry, "dNSHostName"),
                    display_name=_attr_str(entry, "displayName"),
                    templates=templates,
                    web_enrollment=_web_enrollment_from_servers(servers),
                    enrollment_flags=_attr_int(entry, "msPKI-Enrollment-Flag"),
                    security_aces=ca_aces,
                )
            )
    except Exception as exc:
        result.errors.append(f"enrollment services: {exc}")

    if not offered:
        return result

    template_base = f"CN=Certificate Templates,{pki}"
    name_filter = "".join(f"(name={escape_filter_chars(t)})" for t in sorted(offered))
    try:
        session.conn.search(
            search_base=template_base,
            search_filter=f"(&(objectClass=pKICertificateTemplate)(|{name_filter}))",
            search_scope=LEVEL,
            attributes=[
                "name",
                "displayName",
                "msPKI-Enrollment-Flag",
                "pKIExtendedKeyUsage",
                "msPKI-Template-Schema-Version",
                "msPKI-Certificate-Application-Policy",
                "nTSecurityDescriptor",
            ],
            controls=controls,
        )
        for entry in session.conn.entries:
            name = _attr_str(entry, "name") or ""
            flags = _attr_int(entry, "msPKI-Enrollment-Flag")
            template_aces = [
                {"trustee_sid": a.trustee_sid, "rights": list(a.rights)}
                for a in parse_template_sd_from_entry(entry)
            ]
            result.templates.append(
                CertificateTemplateRecord(
                    name=name,
                    display_name=_attr_str(entry, "displayName"),
                    enrollment_flags=flags,
                    extended_key_usage=_attr_list(entry, "pKIExtendedKeyUsage"),
                    schema_version=_attr_int(entry, "msPKI-Template-Schema-Version", 0)
                    or None,
                    low_priv_enrollment=_low_priv_enrollment_from_sd(entry),
                    requires_manager_approval=bool(flags & CT_FLAG_PEND_ALL_REQUESTS),
                    enrollee_supplies_subject=bool(flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
                    security_aces=template_aces,
                )
            )
    except Exception as exc:
        result.errors.append(f"templates: {exc}")

    return result
