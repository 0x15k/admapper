from __future__ import annotations

from dataclasses import dataclass, field

from admapper.acl.parse import parse_security_descriptor
from admapper.acl.rights import (
    AD_GENERIC_ALL,
    AD_GENERIC_WRITE,
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_WRITE_PROP,
    GENERIC_ALL,
    GENERIC_WRITE,
    WRITE_DACL,
    WRITE_OWNER,
)

# Certificate template extended rights (Certipy / AD CS)
GUID_CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# CA management extended rights (ESC7)
GUID_MANAGE_CA = "0e3ae006-8359-11d1-8dd4-00c04fd933c0"
GUID_MANAGE_CERTIFICATES = "0e3ae00b-8359-11d1-8dd4-00c04fd933c0"

_ENROLL_GUIDS = frozenset({GUID_CERTIFICATE_ENROLLMENT, GUID_CERTIFICATE_AUTOENROLLMENT})
_CA_MANAGE_GUIDS = frozenset({GUID_MANAGE_CA, GUID_MANAGE_CERTIFICATES})
_WRITE_MASKS = frozenset({"genericall", "genericwrite", "writedacl", "writeowner", "owns"})


@dataclass
class TemplateAce:
    trustee_sid: str
    rights: list[str] = field(default_factory=list)


def _rights_from_mask(mask) -> list[str]:
    rights: list[str] = []
    if mask.hasPriv(GENERIC_ALL) or mask.hasPriv(AD_GENERIC_ALL):
        rights.append("genericall")
    if mask.hasPriv(GENERIC_WRITE) or mask.hasPriv(AD_GENERIC_WRITE):
        rights.append("genericwrite")
    if mask.hasPriv(WRITE_DACL):
        rights.append("writedacl")
    if mask.hasPriv(WRITE_OWNER):
        rights.append("writeowner")
    if mask.hasPriv(ADS_RIGHT_DS_WRITE_PROP):
        rights.append("writeproperty")
    if mask.hasPriv(ADS_RIGHT_DS_CONTROL_ACCESS):
        rights.append("control_access")
    return rights


def parse_template_security_descriptor(raw: bytes) -> list[TemplateAce]:
    """Parse pKICertificateTemplate nTSecurityDescriptor into trustee rights."""
    from admapper.acl.parse import guid_le_to_str, parse_security_descriptor
    from admapper.acl.parse import _require_impacket

    ldaptypes, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, _, ACE = _require_impacket()

    by_trustee: dict[str, set[str]] = {}

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd.fromString(raw)
    dacl = sd["Dacl"]
    if dacl != b"" and hasattr(dacl, "aces"):
        for ace in dacl.aces:
            if ace["AceType"] not in (
                ACCESS_ALLOWED_ACE.ACE_TYPE,
                ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
            ):
                continue
            if ace.hasFlag(ACE.INHERIT_ONLY_ACE) and not ace.hasFlag(ACE.INHERITED_ACE):
                continue
            body = ace["Ace"]
            trustee = body["Sid"].formatCanonical()
            rights: set[str] = set()
            mask = body["Mask"]
            if mask.hasPriv(GENERIC_ALL) or mask.hasPriv(AD_GENERIC_ALL):
                rights.add("genericall")
            if mask.hasPriv(GENERIC_WRITE) or mask.hasPriv(AD_GENERIC_WRITE):
                rights.add("genericwrite")
            if mask.hasPriv(WRITE_DACL):
                rights.add("writedacl")
            if mask.hasPriv(WRITE_OWNER):
                rights.add("writeowner")
            object_type: str | None = None
            if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                if body.hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    object_type = guid_le_to_str(body["ObjectType"])
                if object_type in _ENROLL_GUIDS:
                    rights.add("enroll")
                if object_type in _CA_MANAGE_GUIDS:
                    rights.add("manage_ca")
            if mask.hasPriv(ADS_RIGHT_DS_CONTROL_ACCESS) and "enroll" not in rights:
                if object_type in _ENROLL_GUIDS:
                    rights.add("enroll")
            if not rights:
                continue
            bucket = by_trustee.setdefault(trustee, set())
            bucket.update(rights)

    # Also merge generic ACL abuse rights from shared parser
    parsed = parse_security_descriptor(raw, object_classes=["pKICertificateTemplate"])
    for ace in parsed.aces:
        rights = set(ace.rights)
        if ace.object_type in _ENROLL_GUIDS:
            rights.add("enroll")
        if not rights:
            continue
        bucket = by_trustee.setdefault(ace.trustee_sid, set())
        bucket.update(rights)

    return [TemplateAce(trustee_sid=sid, rights=sorted(rights)) for sid, rights in by_trustee.items()]


def parse_ca_security_descriptor(raw: bytes) -> list[TemplateAce]:
    """Parse pKIEnrollmentService nTSecurityDescriptor for CA-level rights (ESC7)."""
    parsed = parse_security_descriptor(raw, object_classes=["pKIEnrollmentService"])
    by_trustee: dict[str, set[str]] = {}
    for ace in parsed.aces:
        rights = set(ace.rights)
        if ace.object_type == GUID_MANAGE_CA:
            rights.add("manage_ca")
        if ace.object_type == GUID_MANAGE_CERTIFICATES:
            rights.add("manage_certificates")
        trustee = ace.trustee_sid
        bucket = by_trustee.setdefault(trustee, set())
        bucket.update(rights)
    return [TemplateAce(trustee_sid=sid, rights=sorted(rights)) for sid, rights in by_trustee.items()]


def parse_template_sd_from_entry(entry) -> list[TemplateAce]:
    if not getattr(entry, "nTSecurityDescriptor", None):
        return []
    raw_values = entry.nTSecurityDescriptor.raw_values
    if not raw_values:
        return []
    try:
        return parse_template_security_descriptor(raw_values[0])
    except Exception:
        return []


def parse_ca_sd_from_entry(entry) -> list[TemplateAce]:
    if not getattr(entry, "nTSecurityDescriptor", None):
        return []
    raw_values = entry.nTSecurityDescriptor.raw_values
    if not raw_values:
        return []
    try:
        return parse_ca_security_descriptor(raw_values[0])
    except Exception:
        return []


def ace_has_enroll(ace: TemplateAce) -> bool:
    return "enroll" in ace.rights or "control_access" in ace.rights


def ace_has_template_write(ace: TemplateAce) -> bool:
    return bool(_WRITE_MASKS.intersection(ace.rights)) or "writeproperty" in ace.rights
