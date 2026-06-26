from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from admapper.support.platform import (
    _impacket_status,
    platform_label,
    resolve_hashcat,
    resolve_john,
    resolve_kerbrute,
    resolve_nxc,
    system_name,
)


class SupportTier(StrEnum):
    """How a capability is delivered — determines real cross-platform needs."""

    CORE = "core"  # pip install admapper — pure Python
    RECON = "recon"  # pip install admapper[recon] — impacket (library or subprocess)
    EXTERNAL = "external"  # separate binary on PATH (hashcat, kerbrute, …)


class SupportLevel(StrEnum):
    FULL = "full"  # works on macOS, Linux, Windows with tier deps met
    PARTIAL = "partial"  # works but degraded / needs extra OS setup
    EXPORT = "export"  # ADMapper exports hashes; crack happens outside


@dataclass(frozen=True)
class FeatureSupport:
    feature: str
    command: str
    tier: SupportTier
    level: SupportLevel
    runtime: str
    notes: str


def _impacket_available() -> bool:
    return _impacket_status()[0]


def feature_matrix() -> list[FeatureSupport]:
    """
    Authoritative compatibility matrix for ADMapper as a Python CLI.

    Distribution model: pip package with console script `admapper`.
    Not a standalone binary — requires Python 3.11+ on the host.
    """
    impacket = _impacket_available()
    has_hashcat = resolve_hashcat() is not None
    has_john = resolve_john() is not None
    has_kerbrute = resolve_kerbrute() is not None
    has_nxc = resolve_nxc() is not None

    roast_crack_level = (
        SupportLevel.FULL
        if has_hashcat or has_john
        else SupportLevel.EXPORT
    )
    return [
        FeatureSupport(
            feature="Interactive CLI / workspaces",
            command="admapper start",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="typer + prompt_toolkit + rich",
            notes="Identical on macOS, Linux, Windows after pip install.",
        ),
        FeatureSupport(
            feature="DNS / TCP port scan",
            command="start_unauth",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="dnspython + socket (stdlib)",
            notes="No OS-specific binaries.",
        ),
        FeatureSupport(
            feature="LDAP anonymous probe / user enum",
            command="enum users",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="ldap3",
            notes="LDAP path works everywhere Python runs.",
        ),
        FeatureSupport(
            feature="SAMR / RID / SMB null session",
            command="enum users",
            tier=SupportTier.RECON,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="impacket (Python import)",
            notes="Needs pip install admapper[recon]. Without it: LDAP-only enum.",
        ),
        FeatureSupport(
            feature="AS-REP roasting",
            command="asreproast",
            tier=SupportTier.RECON,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="impacket GetNPUsers via sys.executable",
            notes="Subprocess uses active Python/venv — same on all OS.",
        ),
        FeatureSupport(
            feature="Kerberoasting",
            command="kerberoast",
            tier=SupportTier.RECON,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="impacket GetUserSPNs via sys.executable",
            notes="Requires impacket; preauth may need workspace creds.",
        ),
        FeatureSupport(
            feature="Hash cracking (auto)",
            command="asreproast / kerberoast --wordlist",
            tier=SupportTier.EXTERNAL,
            level=roast_crack_level,
            runtime="hashcat or john (binary)",
            notes="Export always works; auto-crack needs hashcat/john on PATH.",
        ),
        FeatureSupport(
            feature="Password spray (LDAP)",
            command="spray",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="ldap3 SIMPLE bind",
            notes="Default spray path — no external binary required.",
        ),
        FeatureSupport(
            feature="Password spray (kerbrute / nxc)",
            command="spray --method kerbrute|nxc",
            tier=SupportTier.EXTERNAL,
            level=SupportLevel.FULL
            if (has_kerbrute or has_nxc)
            else SupportLevel.PARTIAL,
            runtime="kerbrute or nxc/netexec binary",
            notes="Optional; LDAP spray remains fallback.",
        ),
        FeatureSupport(
            feature="Credential verify (LDAP)",
            command="creds verify",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="ldap3",
            notes="Primary verification path on every OS.",
        ),
        FeatureSupport(
            feature="Credential verify (SMB / Kerberos)",
            command="creds verify",
            tier=SupportTier.RECON,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="impacket SMB + krb5",
            notes="SMB/Kerberos checks skipped if impacket missing.",
        ),
        FeatureSupport(
            feature="Authenticated workflow",
            command="start_auth",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="ldap3 + JSON graph",
            notes="Phase 7 gate + Phase 8 inventory in one command.",
        ),
        FeatureSupport(
            feature="Authenticated LDAP inventory",
            command="start_auth / enum auth",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="ldap3 authenticated search",
            notes="Users, groups, computers, OUs, GPOs, trusts, delegations.",
        ),
        FeatureSupport(
            feature="SMB shares + GPP",
            command="start_auth",
            tier=SupportTier.RECON,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="impacket SMB + GetGPPPassword",
            notes="LDAP-only auth enum works without impacket.",
        ),
        FeatureSupport(
            feature="BloodHound export",
            command="start_auth",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="JSON export to bloodhound/",
            notes="Minimal CE-compatible users/groups/computers JSON.",
        ),
        FeatureSupport(
            feature="Attack path analysis",
            command="paths",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="BFS on graph.json + auth_inventory",
            notes="Owned users → high-value groups; saves paths.json.",
        ),
        FeatureSupport(
            feature="ACL enumeration / abuse mapping",
            command="acls",
            tier=SupportTier.RECON,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="ldap3 + impacket SR_SECURITY_DESCRIPTOR parser",
            notes="Requires impacket for ACE parsing; LDAP bind is ldap3.",
        ),
        FeatureSupport(
            feature="Advanced Kerberos analysis",
            command="kerberos",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="inventory + acl_findings JSON analysis",
            notes="Delegation, shadow creds, backup operators from start_auth data.",
        ),
        FeatureSupport(
            feature="Timeroast candidate export",
            command="timeroast",
            tier=SupportTier.CORE,
            level=SupportLevel.EXPORT,
            runtime="JSON export + manual guide",
            notes="Hash recovery needs external timeroast/nxc binary.",
        ),
        FeatureSupport(
            feature="AD CS enumeration / ESC detection",
            command="adcs",
            tier=SupportTier.RECON,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="ldap3 + impacket SR_SECURITY_DESCRIPTOR for enrollment ACLs",
            notes="Exploitation via external certipy; ADMapper detects + guides.",
        ),
        FeatureSupport(
            feature="Coercion & NTLM relay playbook",
            command="coerce",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="workspace intel → coerce_ops.json + guides",
            notes="Detect/plan only — exploit via ntlmrelayx/PetitPotam externally.",
        ),
        FeatureSupport(
            feature="Post-exploitation playbook",
            command="postex",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="inventory + ACLs/paths → postex_ops.json",
            notes="Lateral/dump/loot planning; execution via Impacket/nxc/mimikatz.",
        ),
        FeatureSupport(
            feature="MSSQL lateral movement",
            command="mssql",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="hosts/SPNs + impacket TDS enum → mssql_inventory.json",
            notes="Detect/plan SQL privesc; exploit via mssqlclient/nxc externally.",
        ),
        FeatureSupport(
            feature="CVE detection & exploit confirm",
            command="cves",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL if impacket else SupportLevel.PARTIAL,
            runtime="inventory OS + LDAP MAQ → cve_findings.json",
            notes="ZeroLogon/noPac require explicit confirm; EternalBlue/PrintNightmare detect-only.",
        ),
        FeatureSupport(
            feature="Reporting & export",
            command="export",
            tier=SupportTier.CORE,
            level=SupportLevel.FULL,
            runtime="aggregate workspace JSON → evidence + technical_report + Navigator",
            notes="export json/txt/navigator; executive PDF planned for future.",
        ),
    ]


def distribution_summary() -> dict[str, str]:
    """One-line facts about how ADMapper is shipped and what that implies."""
    return {
        "package": "pip install admapper  (or pip install -e .[recon] for dev)",
        "entrypoint": "console script `admapper` → Python module",
        "python": ">=3.11",
        "platform": f"{platform_label()} ({system_name()})",
        "config": "Path.home() / '.admapper'  — works on all OS",
        "not": "Not a single native binary; no Docker required by default",
    }
