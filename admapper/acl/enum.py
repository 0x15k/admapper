from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ldap3 import SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from admapper.auth.ldap_session import LdapSession
from admapper.graph.catalog import HIGH_VALUE_GROUPS, is_high_value_group


@dataclass
class AclTarget:
    dn: str
    name: str
    object_type: str
    object_classes: list[str] = field(default_factory=list)


@dataclass
class PrincipalContext:
    username: str
    user_dn: str | None
    user_sid: str
    group_sids: dict[str, str] = field(default_factory=dict)
    sid_to_name: dict[str, str] = field(default_factory=dict)

    @property
    def all_sids(self) -> set[str]:
        return {self.user_sid, *self.group_sids.keys()}


def _attr_str(entry, name: str) -> str | None:
    if not getattr(entry, name, None):
        return None
    return str(getattr(entry, name).value)


def _attr_list(entry, name: str) -> list[str]:
    if not getattr(entry, name, None):
        return []
    return [str(v) for v in getattr(entry, name).values]


def resolve_principal_context(
    session: LdapSession,
    username: str,
    *,
    member_of: list[str] | None = None,
) -> PrincipalContext | None:
    """Resolve objectSid for owned user and transitive group memberships."""
    session.conn.search(
        search_base=session.base_dn,
        search_filter=f"(sAMAccountName={username})",
        search_scope=SUBTREE,
        attributes=["distinguishedName", "objectSid", "memberOf"],
    )
    if not session.conn.entries:
        return None

    entry = session.conn.entries[0]
    user_dn = _attr_str(entry, "distinguishedName")
    sid_raw = entry.objectSid.raw_values[0] if entry.objectSid else None
    if not sid_raw:
        return None

    from impacket.ldap.ldaptypes import LDAP_SID

    user_sid = LDAP_SID(data=sid_raw).formatCanonical()
    sid_to_name = {user_sid: username}
    group_sids: dict[str, str] = {}

    groups = member_of or _attr_list(entry, "memberOf")
    for group_dn in groups:
        session.conn.search(
            search_base=group_dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectSid"],
        )
        if not session.conn.entries:
            continue
        gentry = session.conn.entries[0]
        gname = _attr_str(gentry, "sAMAccountName") or group_dn
        gsid_raw = gentry.objectSid.raw_values[0] if gentry.objectSid else None
        if not gsid_raw:
            continue
        gsid = LDAP_SID(data=gsid_raw).formatCanonical()
        group_sids[gsid] = gname
        sid_to_name[gsid] = gname

    return PrincipalContext(
        username=username,
        user_dn=user_dn,
        user_sid=user_sid,
        group_sids=group_sids,
        sid_to_name=sid_to_name,
    )


def build_acl_targets(
    session: LdapSession,
    inventory: dict[str, Any] | None,
    *,
    max_targets: int = 200,
) -> list[AclTarget]:
    """Phase 8.3 / 10 — high-value LDAP objects to read nTSecurityDescriptor from."""
    targets: list[AclTarget] = []
    seen_dns: set[str] = set()

    def add_target(dn: str, name: str, object_type: str, classes: list[str]) -> None:
        if dn.lower() in seen_dns or len(targets) >= max_targets:
            return
        seen_dns.add(dn.lower())
        targets.append(AclTarget(dn=dn, name=name, object_type=object_type, object_classes=classes))

    session.conn.search(
        search_base=session.base_dn,
        search_filter="(objectClass=domain)",
        search_scope=SUBTREE,
        attributes=["distinguishedName", "name", "objectClass"],
    )
    for entry in session.conn.entries:
        dn = _attr_str(entry, "distinguishedName") or ""
        name = _attr_str(entry, "name") or dn
        classes = _attr_list(entry, "objectClass")
        add_target(dn, name, "domain", classes)

    if inventory:
        for group in inventory.get("groups", []):
            name = str(group.get("name", ""))
            dn = str(group.get("dn", ""))
            if not dn:
                continue
            if is_high_value_group(name) or name.lower() in {"domain users", "domain computers"}:
                add_target(dn, name, "group", ["top", "group"])

        for user in inventory.get("users", []):
            dn = str(user.get("dn", ""))
            username = str(user.get("username", ""))
            if dn and username:
                add_target(dn, username, "user", ["top", "person", "organizationalPerson", "user"])

        for computer in inventory.get("computers", [])[:50]:
            dn = str(computer.get("dn", ""))
            name = str(computer.get("name", ""))
            if dn and name:
                add_target(
                    dn,
                    name,
                    "computer",
                    ["top", "person", "organizationalPerson", "user", "computer"],
                )

        for gpo in inventory.get("gpos", []):
            dn = str(gpo.get("dn", ""))
            name = str(gpo.get("name", ""))
            display_name = str(gpo.get("display_name", ""))
            if dn and name:
                add_target(dn, display_name or name, "gpo", ["top", "groupPolicyContainer"])

    if len(targets) < max_targets:
        session.conn.search(
            search_base=session.base_dn,
            search_filter="(objectClass=msDS-GroupManagedServiceAccount)",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "sAMAccountName", "objectClass"],
        )
        for entry in session.conn.entries:
            dn = _attr_str(entry, "distinguishedName") or ""
            name = _attr_str(entry, "sAMAccountName") or dn
            classes = _attr_list(entry, "objectClass")
            add_target(dn, name.rstrip("$"), "computer", classes)

    if len(targets) < max_targets:
        for group_name in HIGH_VALUE_GROUPS:
            if len(targets) >= max_targets:
                break
            session.conn.search(
                search_base=session.base_dn,
                search_filter=f"(&(objectClass=group)(cn={escape_filter_chars(group_name)}))",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "sAMAccountName", "objectClass"],
            )
            for entry in session.conn.entries:
                dn = _attr_str(entry, "distinguishedName") or ""
                name = _attr_str(entry, "sAMAccountName") or dn
                classes = _attr_list(entry, "objectClass")
                add_target(dn, name, "group", classes)

    return targets


def fetch_security_descriptor(
    session: LdapSession,
    target_dn: str,
) -> bytes | None:
    controls = security_descriptor_control(criticality=True, sdflags=0x04)
    session.conn.search(
        search_base=target_dn,
        search_filter="(objectClass=*)",
        search_scope=SUBTREE,
        attributes=["nTSecurityDescriptor"],
        controls=controls,
    )
    if not session.conn.entries:
        return None
    entry = session.conn.entries[0]
    if not getattr(entry, "nTSecurityDescriptor", None):
        return None
    if hasattr(entry.nTSecurityDescriptor, "raw_values"):
        raw = entry.nTSecurityDescriptor.raw_values
        return raw[0] if raw else None
    value = entry.nTSecurityDescriptor.value
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("latin-1", errors="replace")
    return None
