from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WsusTechnique:
    key: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "wsus_esc"


WSUS_TECHNIQUES: dict[str, WsusTechnique] = {
    "wsus_spoof": WsusTechnique(
        key="wsus_spoof",
        title="WSUS update spoofing",
        severity="critical",
        mitre_id="T1195.002",
        summary="Publish malicious update via WSUS to compromise clients or push rogue certificates.",
        manual_commands=(
            "# Requires WSUS Administrators membership or equivalent",
            "python3 pywsus.py -u <user>@<domain> -p <pass> -s <wsus_host> publish ...",
            "# Or SharpWSUS / manual WSUS API abuse after machine cert auth",
        ),
    ),
    "wsus_cert_chain": WsusTechnique(
        key="wsus_cert_chain",
        title="WSUS + AD CS certificate chain",
        severity="critical",
        mitre_id="T1649",
        summary=(
            "Enroll a restricted template (Server Auth), then abuse WSUS toward DA. "
            "Server-Authentication-only templates cannot be used for certipy auth / PKINIT login."
        ),
        manual_commands=(
            "certipy req -u <user>@<domain> -hashes :<NTLM> -ca <CA> -template <template> -dns <wsus_fqdn>",
            "# EKU = Server Auth only — skip certipy auth; use cert for WSUS HTTPS spoofing",
            "admapper wsus show wsus-004",
            "python3 pywsus.py -s <wsus_host> publish ...",
        ),
    ),
    "wsus_admin_enum": WsusTechnique(
        key="wsus_admin_enum",
        title="WSUS role enumeration",
        severity="medium",
        mitre_id="T1087",
        summary="Enumerate WSUS Administrators / Reporters and ACL paths to WSUS groups.",
        manual_commands=(
            "Get-ADGroupMember 'WSUS Administrators'",
            "bloodyAD --host <DC> get object 'CN=WSUS Administrators,CN=Users,DC=...'",
            "ADMapper acls  # look for AddMember/GenericAll on WSUS Administrators",
        ),
    ),
}


def wsus_meta(key: str) -> WsusTechnique:
    return WSUS_TECHNIQUES.get(
        key,
        WsusTechnique(
            key=key,
            title=key,
            severity="medium",
            mitre_id="T1195.002",
            summary=f"WSUS technique {key}",
            manual_commands=("guide wsus_esc",),
        ),
    )
