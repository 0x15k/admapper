from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from admapper.acl.rights import (
    AD_GENERIC_ALL,
    AD_GENERIC_WRITE,
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_SELF,
    ADS_RIGHT_DS_WRITE_PROP,
    GENERIC_ALL,
    GENERIC_WRITE,
    GUID_ADD_KEY_CREDENTIAL,
    GUID_FORCE_CHANGE_PASSWORD,
    GUID_GET_CHANGES,
    GUID_GET_CHANGES_ALL,
    GUID_GROUP,
    GUID_MEMBER,
    GUID_READ_GMSA,
    GUID_READ_LAPS,
    GUID_SPN,
    GUID_USER,
    WRITE_DACL,
    WRITE_OWNER,
)


def _require_impacket():
    try:
        from impacket.ldap import ldaptypes
        from impacket.ldap.ldaptypes import (
            ACCESS_ALLOWED_ACE,
            ACCESS_ALLOWED_OBJECT_ACE,
            ACCESS_MASK,
            ACE,
        )

        return ldaptypes, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACE
    except ImportError as exc:
        raise ImportError(
            "ACL parsing requires impacket — pip install admapper[recon]"
        ) from exc


def guid_le_to_str(data: bytes) -> str:
    if len(data) != 16:
        return ""
    return (
        f"{data[3]:02x}{data[2]:02x}{data[1]:02x}{data[0]:02x}-"
        f"{data[5]:02x}{data[4]:02x}-"
        f"{data[7]:02x}{data[6]:02x}-"
        f"{data[8]:02x}{data[9]:02x}-"
        f"{data[10]:02x}{data[11]:02x}{data[12]:02x}{data[13]:02x}{data[14]:02x}{data[15]:02x}"
    ).lower()


@dataclass
class ParsedAce:
    trustee_sid: str
    rights: list[str] = field(default_factory=list)
    raw_mask: int = 0
    object_type: str | None = None
    inherited_object_type: str | None = None


@dataclass
class ParsedSecurityDescriptor:
    owner_sid: str | None
    aces: list[ParsedAce] = field(default_factory=list)


def _has_generic_all(mask: Any) -> bool:
    return mask.hasPriv(GENERIC_ALL) or mask.hasPriv(AD_GENERIC_ALL)


def _has_generic_write(mask: Any) -> bool:
    return mask.hasPriv(GENERIC_WRITE) or mask.hasPriv(AD_GENERIC_WRITE)


def _ace_applies_to_class(inherited_guid: str | None, object_classes: list[str]) -> bool:
    if not inherited_guid:
        return True
    class_map = {
        "group": GUID_GROUP,
        "user": GUID_USER,
        "domain": "19195a5a-6da0-11d0-afd3-00c04fd930c9",
        "organizationalunit": "bf967aa5-0de6-11d0-a285-00aa003049e2",
        "computer": "bf967a86-0de6-11d0-a285-00aa003049e2",
    }
    for oc in reversed(object_classes):
        expected = class_map.get(oc.lower())
        if expected and inherited_guid == expected:
            return True
    return False


def _rights_from_ace(
    ace: Any,
    *,
    object_classes: list[str],
    ACCESS_ALLOWED_ACE: Any,
    ACCESS_ALLOWED_OBJECT_ACE: Any,
    ACCESS_MASK: Any,
    ACE: Any,
) -> ParsedAce | None:
    allowed_types = {
        ACCESS_ALLOWED_ACE.ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
    }
    if ace["AceType"] not in allowed_types:
        return None
    if ace.hasFlag(ACE.INHERIT_ONLY_ACE) and not ace.hasFlag(ACE.INHERITED_ACE):
        return None

    body = ace["Ace"]
    mask = body["Mask"]
    trustee = body["Sid"].formatCanonical()
    rights: list[str] = []
    object_type: str | None = None
    inherited_type: str | None = None

    if _has_generic_all(mask):
        return ParsedAce(
            trustee_sid=trustee,
            rights=["genericall"],
            raw_mask=int(mask["Mask"]),
            object_type=object_type,
            inherited_object_type=inherited_type,
        )
    if _has_generic_write(mask):
        rights.append("genericwrite")
    if mask.hasPriv(WRITE_DACL):
        if ace["AceType"] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE or not body.hasFlag(
            ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        ):
            rights.append("writedacl")
    if mask.hasPriv(WRITE_OWNER):
        rights.append("writeowner")

    if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
        if body.hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
            object_type = guid_le_to_str(body["ObjectType"])
        if body.hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
            inherited_type = guid_le_to_str(body["InheritedObjectType"])
            if not _ace_applies_to_class(inherited_type, object_classes):
                return ParsedAce(trustee_sid=trustee, rights=[], raw_mask=mask["Mask"])

        if mask.hasPriv(ADS_RIGHT_DS_CONTROL_ACCESS):
            if object_type == GUID_FORCE_CHANGE_PASSWORD:
                rights.append("forcechangepassword")
            elif object_type == GUID_GET_CHANGES:
                rights.append("dcsync_partial")
            elif object_type == GUID_GET_CHANGES_ALL:
                rights.append("dcsync")
            elif object_type == GUID_READ_LAPS:
                rights.append("readlapspassword")
            elif object_type == GUID_READ_GMSA:
                rights.append("readgmsapassword")
            elif object_type == GUID_ADD_KEY_CREDENTIAL:
                rights.append("genericwrite")

        if mask.hasPriv(ADS_RIGHT_DS_WRITE_PROP):
            if object_type in {GUID_MEMBER, None}:
                rights.append("addmember")
            if object_type == GUID_SPN:
                rights.append("writespn")

        if mask.hasPriv(ADS_RIGHT_DS_SELF):
            if object_type in {GUID_MEMBER, GUID_GROUP, None}:
                rights.append("addself")

        if mask.hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD):
            if object_type == GUID_USER:
                rights.append("genericwrite")

    # DCSync needs both rights on domain — partial tracked separately
    deduped = list(dict.fromkeys(rights))
    return ParsedAce(
        trustee_sid=trustee,
        rights=deduped,
        raw_mask=int(mask["Mask"]),
        object_type=object_type,
        inherited_object_type=inherited_type,
    )


def parse_security_descriptor(
    raw_sd: bytes,
    *,
    object_classes: list[str] | None = None,
) -> ParsedSecurityDescriptor:
    """Parse nTSecurityDescriptor bytes into owner SID and abuse-relevant ACEs."""
    (
        ldaptypes,
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_MASK,
        ACE,
    ) = _require_impacket()

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd.fromString(raw_sd)
    owner_sid = None
    if sd["OwnerSid"] != b"":
        owner_sid = sd["OwnerSid"].formatCanonical()

    classes = object_classes or []
    aces: list[ParsedAce] = []
    dacl = sd["Dacl"]
    if dacl != b"" and hasattr(dacl, "aces"):
        for ace in dacl.aces:
            parsed = _rights_from_ace(
                ace,
                object_classes=classes,
                ACCESS_ALLOWED_ACE=ACCESS_ALLOWED_ACE,
                ACCESS_ALLOWED_OBJECT_ACE=ACCESS_ALLOWED_OBJECT_ACE,
                ACCESS_MASK=ACCESS_MASK,
                ACE=ACE,
            )
            if parsed and parsed.rights:
                aces.append(parsed)

    # Combine partial DCSync rights
    trustees_dcsync: dict[str, set[str]] = {}
    for ace in aces:
        trustees_dcsync.setdefault(ace.trustee_sid, set()).update(ace.rights)
    for sid, rset in trustees_dcsync.items():
        if "dcsync_partial" in rset and "dcsync" in rset:
            continue
        if rset == {"dcsync_partial"}:
            pass  # keep partial until pair found

    merged: list[ParsedAce] = []
    seen: set[tuple[str, str]] = set()
    for ace in aces:
        rights = [r for r in ace.rights if r not in ("dcsync", "dcsync_partial")]
        other = trustees_dcsync.get(ace.trustee_sid, set())
        if "dcsync" in other and "dcsync_partial" in other:
            if "dcsync" not in rights:
                rights.append("dcsync")
        for right in rights:
            key = (ace.trustee_sid, right)
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                ParsedAce(
                    trustee_sid=ace.trustee_sid,
                    rights=[right],
                    raw_mask=ace.raw_mask,
                    object_type=ace.object_type,
                    inherited_object_type=ace.inherited_object_type,
                )
            )

    return ParsedSecurityDescriptor(owner_sid=owner_sid, aces=merged)


def owner_abuse_right(owner_sid: str | None, principal_sids: set[str]) -> str | None:
    if owner_sid and owner_sid in principal_sids:
        return "owns"
    return None
