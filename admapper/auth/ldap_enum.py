from __future__ import annotations

from dataclasses import dataclass, field

from ldap3 import SUBTREE

from admapper.auth.ldap_session import LdapSession
from admapper.models.ad_object import (
    ComputerRecord,
    DelegationRecord,
    GpoRecord,
    GroupRecord,
    OuRecord,
    TrustRecord,
)
from admapper.models.user import UserRecord, apply_uac_flags

UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
UAC_ACCOUNTDISABLE = 0x000002


@dataclass
class LdapAuthEnumResult:
    users: list[UserRecord] = field(default_factory=list)
    groups: list[GroupRecord] = field(default_factory=list)
    computers: list[ComputerRecord] = field(default_factory=list)
    ous: list[OuRecord] = field(default_factory=list)
    gpos: list[GpoRecord] = field(default_factory=list)
    delegations: list[DelegationRecord] = field(default_factory=list)
    trusts: list[TrustRecord] = field(default_factory=list)
    adcs_present: bool = False
    domain_gplink: str | None = None
    errors: list[str] = field(default_factory=list)


def _attr_str(entry, name: str) -> str | None:
    if not getattr(entry, name, None):
        return None
    return str(getattr(entry, name).value)


def _attr_list(entry, name: str) -> list[str]:
    if not getattr(entry, name, None):
        return []
    return [str(v) for v in getattr(entry, name).values]


def _search(session: LdapSession, filter_query: str, attributes: list[str]) -> list:
    session.conn.search(
        search_base=session.base_dn,
        search_filter=filter_query,
        search_scope=SUBTREE,
        attributes=attributes,
    )
    return list(session.conn.entries)


def _user_from_entry(entry, sources: list[str]) -> UserRecord | None:
    username = _attr_str(entry, "sAMAccountName") or ""
    if not username:
        return None
    uac_raw = entry.userAccountControl.value if entry.userAccountControl else None
    uac = int(uac_raw) if uac_raw is not None else None
    spns = _attr_list(entry, "servicePrincipalName")
    admin_count = None
    if hasattr(entry, "adminCount") and entry.adminCount:
        try:
            admin_count = int(entry.adminCount.value)
        except (ValueError, TypeError):
            pass
    user = apply_uac_flags(
        UserRecord(
            username=username,
            sources=list(sources),
            description=_attr_str(entry, "description"),
            dn=_attr_str(entry, "distinguishedName"),
            uac=uac,
            spns=spns,
            member_of=_attr_list(entry, "memberOf"),
            admin_count=admin_count,
        )
    )
    return user


def enumerate_ldap_authenticated(session: LdapSession) -> LdapAuthEnumResult:
    """Phase 8.1–8.2, 8.6, 8.7 — authenticated LDAP inventory."""
    result = LdapAuthEnumResult()

    try:
        for entry in _search(
            session,
            "(&(objectClass=user)(objectCategory=person))",
            [
                "sAMAccountName",
                "userAccountControl",
                "servicePrincipalName",
                "description",
                "distinguishedName",
                "memberOf",
                "adminCount",
            ],
        ):
            user = _user_from_entry(entry, ["ldap_auth"])
            if not user:
                continue
            result.users.append(user)
            _collect_delegation_user(entry, user.username, "user", result)
    except Exception as exc:
        result.errors.append(f"users: {exc}")

    try:
        for entry in _search(
            session,
            "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))",
            [
                "sAMAccountName",
                "userAccountControl",
                "servicePrincipalName",
                "description",
                "distinguishedName",
                "memberOf",
                "adminCount",
            ],
        ):
            user = _user_from_entry(entry, ["ldap_auth", "msa"])
            if not user:
                continue
            result.users.append(user)
            _collect_delegation_user(entry, user.username, "user", result)
    except Exception as exc:
        result.errors.append(f"msa: {exc}")

    try:
        for entry in _search(
            session,
            "(objectClass=group)",
            ["sAMAccountName", "distinguishedName", "description", "member"],
        ):
            name = _attr_str(entry, "sAMAccountName") or ""
            if not name:
                continue
            result.groups.append(
                GroupRecord(
                    name=name,
                    dn=_attr_str(entry, "distinguishedName"),
                    description=_attr_str(entry, "description"),
                    members=_attr_list(entry, "member"),
                )
            )
    except Exception as exc:
        result.errors.append(f"groups: {exc}")

    try:
        for entry in _search(
            session,
            "(objectClass=computer)",
            [
                "sAMAccountName",
                "distinguishedName",
                "dNSHostName",
                "operatingSystem",
                "userAccountControl",
                "msDS-AllowedToDelegateTo",
                "pwdLastSet",
                "lastLogonTimestamp",
            ],
        ):
            name = _attr_str(entry, "sAMAccountName") or ""
            if not name:
                continue
            uac_raw = entry.userAccountControl.value if entry.userAccountControl else None
            uac = int(uac_raw) if uac_raw is not None else 0
            
            pwd_last_set = None
            if hasattr(entry, "pwdLastSet") and entry.pwdLastSet:
                try:
                    pwd_last_set = int(entry.pwdLastSet.value)
                except (ValueError, TypeError):
                    pass
            
            last_logon = None
            if hasattr(entry, "lastLogonTimestamp") and entry.lastLogonTimestamp:
                try:
                    last_logon = int(entry.lastLogonTimestamp.value)
                except (ValueError, TypeError):
                    pass

            computer = ComputerRecord(
                name=name.rstrip("$"),
                dn=_attr_str(entry, "distinguishedName"),
                dns_host=_attr_str(entry, "dNSHostName"),
                operating_system=_attr_str(entry, "operatingSystem"),
                enabled=not bool(uac & UAC_ACCOUNTDISABLE),
                unconstrained_delegation=bool(uac & UAC_TRUSTED_FOR_DELEGATION),
                pwd_last_set=pwd_last_set,
                last_logon_timestamp=last_logon,
            )
            result.computers.append(computer)
            _collect_delegation_computer(entry, computer.name, result)
    except Exception as exc:
        result.errors.append(f"computers: {exc}")

    try:
        for entry in _search(
            session,
            "(objectClass=organizationalUnit)",
            ["name", "distinguishedName", "gPLink"],
        ):
            name = _attr_str(entry, "name") or ""
            if name:
                gplink = _attr_str(entry, "gPLink")
                result.ous.append(
                    OuRecord(
                        name=name,
                        dn=_attr_str(entry, "distinguishedName"),
                        gplink=gplink,
                    )
                )
    except Exception as exc:
        result.errors.append(f"ous: {exc}")

    try:
        policies_base = f"CN=Policies,CN=System,{session.base_dn}"
        session.conn.search(
            search_base=policies_base,
            search_filter="(objectClass=groupPolicyContainer)",
            search_scope=SUBTREE,
            attributes=["name", "distinguishedName", "displayName"],
        )
        for entry in session.conn.entries:
            name = _attr_str(entry, "name") or ""
            if name:
                result.gpos.append(
                    GpoRecord(
                        name=name,
                        dn=_attr_str(entry, "distinguishedName"),
                        display_name=_attr_str(entry, "displayName"),
                    )
                )
    except Exception as exc:
        result.errors.append(f"gpos: {exc}")

    try:
        session.conn.search(
            search_base=session.base_dn,
            search_filter="(objectClass=domain)",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "gPLink"],
        )
        if session.conn.entries:
            entry = session.conn.entries[0]
            if getattr(entry, "gPLink", None):
                result.domain_gplink = _attr_str(entry, "gPLink")
    except Exception as exc:
        result.errors.append(f"domain_gplink: {exc}")

    try:
        for entry in _search(
            session,
            "(objectClass=trustedDomain)",
            ["name", "flatName", "trustDirection", "trustType"],
        ):
            result.trusts.append(
                TrustRecord(
                    name=_attr_str(entry, "name") or "",
                    flat_name=_attr_str(entry, "flatName"),
                    direction=_attr_str(entry, "trustDirection"),
                    trust_type=_attr_str(entry, "trustType"),
                )
            )
    except Exception as exc:
        result.errors.append(f"trusts: {exc}")

    try:
        adcs = _search(
            session,
            "(objectClass=pKIEnrollmentService)",
            ["cn", "distinguishedName"],
        )
        result.adcs_present = len(adcs) > 0
    except Exception as exc:
        result.errors.append(f"adcs: {exc}")

    return result


def _collect_delegation_user(
    entry,
    name: str,
    object_type: str,
    result: LdapAuthEnumResult,
) -> None:
    uac_raw = entry.userAccountControl.value if entry.userAccountControl else None
    uac = int(uac_raw) if uac_raw is not None else 0
    dn = _attr_str(entry, "distinguishedName")
    if uac & UAC_TRUSTED_FOR_DELEGATION:
        result.delegations.append(
            DelegationRecord(
                object_name=name,
                object_type=object_type,
                delegation_type="unconstrained",
                dn=dn,
            )
        )
    constrained = _attr_list(entry, "msDS-AllowedToDelegateTo")
    if constrained:
        dtype = (
            "constrained_pt"
            if uac & UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
            else "constrained"
        )
        result.delegations.append(
            DelegationRecord(
                object_name=name,
                object_type=object_type,
                delegation_type=dtype,
                targets=constrained,
                dn=dn,
            )
        )
    rbcd = _attr_str(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
    if rbcd:
        result.delegations.append(
            DelegationRecord(
                object_name=name,
                object_type=object_type,
                delegation_type="rbcd",
                targets=[rbcd],
                dn=dn,
            )
        )


def _collect_delegation_computer(
    entry,
    name: str,
    result: LdapAuthEnumResult,
) -> None:
    _collect_delegation_user(entry, name, "computer", result)
