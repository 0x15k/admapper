from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EdgeCatalogEntry:
    key: str
    title: str
    mitre_id: str | None
    severity: str
    narrative: str
    next_steps: tuple[str, ...] = ()


EDGE_CATALOG: dict[str, EdgeCatalogEntry] = {
    "member_of": EdgeCatalogEntry(
        key="member_of",
        title="Group membership",
        mitre_id="T1087.002",
        severity="info",
        narrative="{source} is a direct member of {target}.",
        next_steps=("Check nested group chains toward Domain Admins", "guide auth_enum"),
    ),
    "member_of_domain": EdgeCatalogEntry(
        key="member_of_domain",
        title="Domain membership",
        mitre_id=None,
        severity="info",
        narrative="{source} belongs to domain {target}.",
    ),
    "unconstrained_delegation": EdgeCatalogEntry(
        key="unconstrained_delegation",
        title="Unconstrained delegation",
        mitre_id="T1558",
        severity="high",
        narrative="{source} has unconstrained Kerberos delegation.",
        next_steps=("Coerce authentication to delegated host", "guide auth_enum"),
    ),
    "constrained_delegation": EdgeCatalogEntry(
        key="constrained_delegation",
        title="Constrained delegation",
        mitre_id="T1558",
        severity="medium",
        narrative="{source} can delegate to: {targets}.",
        next_steps=("Abuse S4U2Self/S4U2Proxy if protocol allowed",),
    ),
    "rbcd": EdgeCatalogEntry(
        key="rbcd",
        title="Resource-based constrained delegation",
        mitre_id="T1134.001",
        severity="high",
        narrative="{source} has RBCD configured (msDS-AllowedToActOnBehalfOfOtherIdentity).",
        next_steps=("Add msDS-AllowedToActOnBehalfOfOtherIdentity if writable",),
    ),
    "owns": EdgeCatalogEntry(
        key="owns",
        title="Compromised principal",
        mitre_id="T1078",
        severity="critical",
        narrative="{source} is marked owned in the workspace.",
        next_steps=("paths show", "start_auth with recovered creds"),
    ),
    "genericall": EdgeCatalogEntry(
        key="genericall",
        title="GenericAll",
        mitre_id="T1098",
        severity="critical",
        narrative="{source} has GenericAll over {target}.",
        next_steps=("acls show", "guide acl_abuse"),
    ),
    "genericwrite": EdgeCatalogEntry(
        key="genericwrite",
        title="GenericWrite",
        mitre_id="T1098",
        severity="high",
        narrative="{source} has GenericWrite over {target}.",
        next_steps=("acls show", "pywhisker / rbcd"),
    ),
    "writedacl": EdgeCatalogEntry(
        key="writedacl",
        title="WriteDACL",
        mitre_id="T1098",
        severity="critical",
        narrative="{source} can modify DACL on {target} — grant GenericAll.",
        next_steps=("dacledit.py", "guide acl_abuse"),
    ),
    "writeowner": EdgeCatalogEntry(
        key="writeowner",
        title="WriteOwner",
        mitre_id="T1098",
        severity="high",
        narrative="{source} can take ownership of {target}.",
        next_steps=("owneredit.py", "dacledit.py"),
    ),
    "forcechangepassword": EdgeCatalogEntry(
        key="forcechangepassword",
        title="ForceChangePassword",
        mitre_id="T1098",
        severity="high",
        narrative="{source} can reset password on {target}.",
        next_steps=("creds add", "start_auth"),
    ),
    "addmember": EdgeCatalogEntry(
        key="addmember",
        title="AddMember",
        mitre_id="T1098",
        severity="critical",
        narrative="{source} can add members to {target}.",
        next_steps=("paths", "start_auth as new group member"),
    ),
    "addself": EdgeCatalogEntry(
        key="addself",
        title="AddSelf",
        mitre_id="T1098",
        severity="critical",
        narrative="{source} can add itself to {target}.",
        next_steps=("paths", "start_auth"),
    ),
    "readlapspassword": EdgeCatalogEntry(
        key="readlapspassword",
        title="ReadLAPSPassword",
        mitre_id="T1555",
        severity="high",
        narrative="{source} can read LAPS password for {target}.",
    ),
    "readgmsapassword": EdgeCatalogEntry(
        key="readgmsapassword",
        title="ReadGMSAPassword",
        mitre_id="T1555",
        severity="high",
        narrative="{source} can read gMSA password for {target}.",
    ),
    "writespn": EdgeCatalogEntry(
        key="writespn",
        title="WriteSPN",
        mitre_id="T1558",
        severity="high",
        narrative="{source} can write SPN on {target} — targeted Kerberoast.",
        next_steps=("kerberoast", "guide kerberoast"),
    ),
    "dcsync": EdgeCatalogEntry(
        key="dcsync",
        title="DCSync",
        mitre_id="T1003.006",
        severity="critical",
        narrative="{source} can DCSync the domain via {target}.",
        next_steps=("secretsdump.py", "guide acl_abuse"),
    ),
    "constrained_pt": EdgeCatalogEntry(
        key="constrained_pt",
        title="Constrained delegation (PT)",
        mitre_id="T1558",
        severity="high",
        narrative="{source} has constrained delegation with protocol transition to {target}.",
        next_steps=("getST.py", "guide kerberos_adv"),
    ),
    "shadow_credentials": EdgeCatalogEntry(
        key="shadow_credentials",
        title="Shadow Credentials",
        mitre_id="T1098",
        severity="high",
        narrative="{source} can add KeyCredentialLink on {target}.",
        next_steps=("pywhisker", "guide kerberos_adv"),
    ),
    "backup_operators": EdgeCatalogEntry(
        key="backup_operators",
        title="Backup Operators",
        mitre_id="T1098",
        severity="high",
        narrative="{source} is in Backup Operators — registry access on DCs.",
        next_steps=("diskshadow", "guide kerberos_adv"),
    ),
    "timeroast": EdgeCatalogEntry(
        key="timeroast",
        title="Timeroasting",
        mitre_id="T1558.003",
        severity="medium",
        narrative="{source} is a timeroast candidate (machine account).",
        next_steps=("timeroast", "guide timeroasting"),
    ),
    "adminto": EdgeCatalogEntry(
        key="adminto",
        title="AdminTo",
        mitre_id="T1021",
        severity="high",
        narrative="{source} has admin access to {target}.",
        next_steps=("postex", "guide postex_local"),
    ),
}

HIGH_VALUE_GROUPS: frozenset[str] = frozenset(
    {
        "domain admins",
        "enterprise admins",
        "administrators",
        "schema admins",
        "account operators",
        "backup operators",
        "dns admins",
        "group policy creator owners",
        "server operators",
        "print operators",
    }
)


def is_high_value_group(name: str) -> bool:
    return name.strip().lower() in HIGH_VALUE_GROUPS


def edge_meta(edge_type: str) -> EdgeCatalogEntry:
    return EDGE_CATALOG.get(
        edge_type,
        EdgeCatalogEntry(
            key=edge_type,
            title=edge_type.replace("_", " ").title(),
            mitre_id=None,
            severity="info",
            narrative="{source} → {target} via {edge_type}.",
        ),
    )
