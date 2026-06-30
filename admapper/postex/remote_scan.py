from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.postex.creds import resolve_winrm_cred
from admapper.postex.evil_winrm_output import extract_winrm_command_body, strip_evil_winrm_output
from admapper.postex.hijack_intel import (
    extract_hijack_intel,
    intel_from_com_tasks,
    parse_schtasks_list_output,
    parse_task_xml_file_output,
)
from admapper.postex.loot_intel import scan_loot_directory
from admapper.postex.pe_arch import (
    infer_arch_from_monitor_log,
    normalize_arch,
    ps_read_pe_arch_script,
)
from admapper.postex.task_hijack import TaskHijackAnalysis, analysis_to_dict, analyze_task_hijack
from admapper.support.output import print_info, print_success, print_warning
from admapper.support.provenance import Tool, print_ok, print_step, print_warn
from admapper.winrm.client import WinRMClient, WinRMError
from admapper.winrm.factory import winrm_client_for_cred

if TYPE_CHECKING:
    from admapper.support.session import Session


_SERVICE_LOG_PATHS: tuple[str, ...] = (
    r"C:\ProgramData\{name}\Logs\monitor.log",
    r"C:\ProgramData\{name}\Logs\app.log",
    r"C:\ProgramData\{name}\Logs\service.log",
    r"C:\ProgramData\{name}\Logs\error.log",
    r"C:\ProgramData\{name}\monitor.log",
    r"C:\ProgramData\{name}\app.log",
    r"C:\ProgramData\{name}\service.log",
)


# Generates potential service log paths; environment-agnostic
def _service_log_candidates(drop_path: str) -> list[str]:
    base = drop_path.rstrip("\\/").split("\\")[-1]
    return [p.format(name=base) for p in _SERVICE_LOG_PATHS]


# Fast targeted queries before full schtasks /query (slow via evil-winrm)
_TARGETED_TASK_QUERIES: tuple[tuple[str, str], ...] = ()


def _ps_com_tasks_recursive(filter_text: str | None) -> str:
    filter_clause = ""
    if filter_text:
        safe = filter_text.replace("'", "''")
        filter_clause = f"if($name -notmatch '{safe}'){{return}}"
    return (
        "$s=New-Object -ComObject Schedule.Service;$s.Connect();"
        "function Walk($folder){"
        "$folder.GetTasks(0)|ForEach-Object{"
        "$name=$_.Name;"
        f"{filter_clause}"
        "$a=$_.Definition.Actions.Item(1);"
        "Write-Output ($name+'|'+$_.Definition.Principal.UserId+'|'+$a.Path+'|'+$a.Arguments)};"
        "$folder.GetFolders(0)|ForEach-Object{Walk $_}};"
        "Walk $s.GetFolder('\\')"
    )


def _ps_get_scheduled_tasks(filter_text: str | None) -> str:
    filter_clause = ""
    if filter_text:
        safe = filter_text.replace("'", "''")
        filter_clause = f"|Where-Object{{$_.TaskName -match '{safe}'}}"
    return (
        f"Get-ScheduledTask -ErrorAction SilentlyContinue{filter_clause}|ForEach-Object{{"
        "$a=$_.Actions|Select-Object -First 1;"
        "$user=$_.Principal.UserId;"
        "if(-not $user -and $_.Principal){$user=$_.Principal.ToString()};"
        "Write-Output ($_.TaskName+'|'+$user+'|'+$a.Execute+'|'+$a.Arguments)}"
    )


def _ps_tasks_from_xml() -> str:
    """Enumerate tasks from on-disk XML (includes subfolders; no COM filter)."""
    return (
        "$root=$env:windir+'\\System32\\Tasks';"
        "Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue|"
        "ForEach-Object{"
        "try{"
        "[xml]$x=Get-Content -LiteralPath $_.FullName -ErrorAction Stop;"
        "$pr=$x.Task.Principals.Principal|Select-Object -First 1;"
        "$act=$x.Task.Actions.Exec|Select-Object -First 1;"
        "$u=if($pr.UserId){$pr.UserId}else{$pr.GroupId};"
        "Write-Output ($_.BaseName+'|'+$u+'|'+$act.Command+'|'+$act.Arguments)"
        "}catch{}}"
    )


def _normalize_task_enum_output(raw: str) -> str:
    text = strip_evil_winrm_output(raw)
    if "<Task" in text or "<task" in text.lower():
        parsed = parse_task_xml_file_output(text)
        if parsed.strip():
            return parsed
    if "TaskName:" in text:
        parsed = parse_schtasks_list_output(text)
        if parsed.strip():
            return parsed
    return text


def _pipe_line_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if "|" in line.strip())


def _has_hijack_payload_hint(text: str) -> bool:
    return bool(
        re.search(
            r"\.zip|\.dll|monitor|update check|loading update|no updates found locally",
            text,
            re.I,
        )
    )


def _clean_monitor_log(monitor_log: str) -> str:
    return extract_winrm_command_body(monitor_log).strip()


def _cmd_type_file(path: str) -> str:
    return f'cmd.exe /c type "{path}"'


def _local_monitor_from_loot(loot_dir, *, drop_path: str = "") -> str:
    if not loot_dir.is_dir():
        return ""
    drop_hints = {drop_path.lower().rstrip("\\/")} if drop_path else set()
    for path in sorted(loot_dir.rglob("*.log")):
        if not path.is_file():
            continue
        in_drop = any(h in str(path).lower() for h in drop_hints)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if in_drop or _has_hijack_payload_hint(text):
            return text.strip()
    return ""

def _monitor_usable(monitor_log: str) -> bool:
    text = _clean_monitor_log(monitor_log)
    if not text:
        return False
    return bool(_has_hijack_payload_hint(text) or re.search(r"ProgramData[/\\].*\.zip", text, re.I))

def _intel_sufficient(
    intel,
    monitor_log: str = "",
    *,
    loot: Any = None,
    drop_path: str = "",
) -> bool:
    """Enough to build DLL-hijack finding without slow full schtasks."""
    if intel and intel.payload_zip:
        return True
    if loot and (loot.zip_dll_refs or loot.dll_hijack_refs):
        return True
    if drop_path and _monitor_usable(monitor_log):
        return True
    return False


def _merge_task_lines(*chunks: str) -> str:
    seen: set[str] = set()
    merged: list[str] = []
    for chunk in chunks:
        for line in chunk.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            key = line.split("|", 1)[0].strip().lower()
            if key in seen:
                continue
            seen.add(key)
            merged.append(line)
    return "\n".join(merged)


def _enumerate_scheduled_tasks(
    client: WinRMClient,
    filter_text: str | None,
) -> tuple[str, str]:
    """Enumerate scheduled tasks via COM (recursive), schtasks, and Get-ScheduledTask."""
    chunks: list[str] = []
    methods: list[str] = []

    enum_attempts: list[tuple[str, str, str]] = [
        *[(name, script, "cmd") for name, script in _TARGETED_TASK_QUERIES],
        ("schtasks", "schtasks /query /fo LIST /v", "cmd"),
        ("tasks_xml", _ps_tasks_from_xml(), "powershell"),
        ("com_recursive", _ps_com_tasks_recursive(filter_text), "powershell"),
        ("get_scheduledtask", _ps_get_scheduled_tasks(filter_text), "powershell"),
    ]
    for method, script, shell in enum_attempts:
        try:
            proc = client.execute(script, shell=shell)
            raw = _normalize_task_enum_output((proc.stdout or "").strip())
            if not raw or _pipe_line_count(raw) == 0:
                continue
            chunks.append(raw)
            methods.append(method)
            print_ok(
                f"task enum ({method}): {_pipe_line_count(raw)} task(s)",
                source=Tool.ADMAPPER,
            )
            if _has_hijack_payload_hint(raw):
                break
        except WinRMError as exc:
            print_warning(f"task enum ({method}): {exc}")
            continue

    merged = _merge_task_lines(*chunks)
    if not merged and filter_text:
        print_info("task enum: filter returned nothing — retrying without filter")
        for method, script, shell in (
            ("com_recursive", _ps_com_tasks_recursive(None), "powershell"),
            ("get_scheduledtask", _ps_get_scheduled_tasks(None), "powershell"),
            ("tasks_xml", _ps_tasks_from_xml(), "powershell"),
        ):
            try:
                proc = client.execute(script, shell=shell)
                raw = _normalize_task_enum_output((proc.stdout or "").strip())
                if not raw or _pipe_line_count(raw) == 0:
                    continue
                chunks.append(raw)
                methods.append(f"{method}_unfiltered")
                print_ok(
                    f"task enum ({method}, unfiltered): {_pipe_line_count(raw)} task(s)",
                    source=Tool.ADMAPPER,
                )
                if _has_hijack_payload_hint(raw):
                    break
            except WinRMError:
                continue
        merged = _merge_task_lines(*chunks)
    if not merged:
        raw_hint = (getattr(client, "last_raw_output", "") or "")[:500]
        if raw_hint:
            print_warning(f"task enum: no parsed output — raw nxc: {raw_hint[:200]}…")
        else:
            print_warning(
                "task enum: no output — COM/schtasks/xml empty (check WinRM or permissions)"
            )
    return merged, "+".join(methods)


# Generic: searches *.log/*.txt modified in last 30 days — not tied to any log path
def _ps_discover_error_logs() -> str:
    return (
        "Get-ChildItem -Path $env:ProgramData -Recurse "
        "-Include *.log,*.txt -ErrorAction SilentlyContinue "
        "| Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) "
        "  -and $_.Length -gt 0 } "
        "| Sort-Object LastWriteTime -Descending "
        "| Select-Object -First 5 -ExpandProperty FullName"
    )


# Fallback paths for logs; environment-agnostic check
def _service_candidate_paths(intel) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()

    def _add(path: str) -> None:
        key = path.lower()
        if key not in seen:
            seen.add(key)
            paths.append(path)

    if intel and intel.monitor_log_path:
        _add(intel.monitor_log_path)
    if intel and intel.drop_path:
        base = intel.drop_path.rstrip("\\/")
        for suffix in (r"\Logs\monitor.log", r"\Logs\app.log", r"\Logs\service.log", r"\Logs\error.log",
               r"\monitor.log", r"\app.log", r"\service.log"):
            _add(base + suffix)
        for candidate in _service_log_candidates(intel.drop_path):
            _add(candidate)
    return paths


# Probes for service logs generically; environment-agnostic
def _probe_service_logs(client: WinRMClient, intel=None) -> tuple[str, str]:
    """Return ``(log_excerpt, winning_path)`` — path is empty if nothing matched."""
    discovered: list[str] = []
    try:
        proc = client.execute(_ps_discover_error_logs(), shell="powershell")
        for line in (proc.stdout or "").splitlines():
            path = line.strip()
            if path.lower().endswith(".log") and ":\\" in path:
                discovered.append(path)
    except WinRMError:
        pass

    for path in [*discovered, *_service_candidate_paths(intel)]:
        for script, shell in (
            (_cmd_type_file(path), "cmd"),
            (_ps_service_log(path), "powershell"),
        ):
            try:
                proc = client.execute(script, shell=shell)
                text = _clean_monitor_log((proc.stdout or "").strip())
                if text and _monitor_usable(text):
                    print_ok(
                        f"service log ({path}): {len(text.splitlines())} line(s)",
                        source=Tool.ADMAPPER,
                    )
                    return text, path
            except WinRMError:
                continue
    return "", ""


def _ps_service_log(path: str) -> str:
    safe = path.replace("'", "''")
    return f"if(Test-Path -LiteralPath '{safe}'){{Get-Content -LiteralPath '{safe}' -Tail 25}}"


def _ps_service_log_candidates(paths: list[str]) -> str:
    checks = []
    for p in paths:
        safe = p.replace("'", "''")
        checks.append(
            f"if(Test-Path -LiteralPath '{safe}')"
            f"{{Get-Content -LiteralPath '{safe}' -Tail 25;break}}"
        )
    return ";".join(checks) if checks else "Write-Output ''"


def _ps_acl(path: str) -> str:
    safe = path.replace("'", "''")
    return f"icacls '{safe}' 2>&1"


@dataclass
class RemoteScanResult:
    analysis: TaskHijackAnalysis = field(default_factory=TaskHijackAnalysis)
    shell_user: str = ""
    dc_ip: str = ""
    errors: list[str] = field(default_factory=list)
    output_path: str | None = None


def _write_scan_payload(
    ws_path,
    *,
    cred,
    domain: str,
    result: RemoteScanResult,
    task_enum_method: str,
    com_out: str,
    nxc_raw: str = "",
):
    out_path = ws_path / "postex_scan.json"
    payload = {
        "dc_ip": cred.host,
        "domain": domain,
        "shell_user": cred.username,
        "errors": result.errors,
        "task_enum_method": task_enum_method,
        "com_task_raw": com_out[:4000] if com_out else "",
        "nxc_raw_excerpt": (nxc_raw or "")[:2000],
        **analysis_to_dict(result.analysis),
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result.output_path = str(out_path)
    return out_path


def run_remote_task_hijack_scan(session: Session, *, host: str | None = None) -> RemoteScanResult:
    """WinRM scan: COM scheduled tasks + writable drop paths for DLL hijack."""
    result = RemoteScanResult()
    if session.workspace is None:
        result.errors.append("no workspace")
        return result

    ws_path = session.workspaces.path_for(session.workspace.name)
    domain = session.workspace.domain or ""
    if not domain:
        result.errors.append("workspace domain not set")
        return result

    loot = scan_loot_directory(ws_path / "loot")
    intel = extract_hijack_intel(loot)
    prev = None
    scan_path = ws_path / "postex_scan.json"
    if scan_path.is_file():
        try:
            prev = json.loads(scan_path.read_text(encoding="utf-8"))
            hi = prev.get("hijack_intel") or {}
            if intel is None and hi.get("drop_path"):
                intel = extract_hijack_intel(
                    loot, monitor_log=str(prev.get("monitor_log_excerpt") or "")
                )
        except (json.JSONDecodeError, OSError):
            prev = None

    try:
        cred = resolve_winrm_cred(session, host=host)
    except ValueError as exc:
        result.errors.append(str(exc))
        return result

    result.dc_ip = cred.host
    result.shell_user = cred.username

    # Phase 1: COM tasks (filter from intel when available)
    client = winrm_client_for_cred(cred, session)

    print_step(
        f"remote post-ex scan @ {cred.host} as {cred.domain}\\{cred.username} (COM Task Scheduler)",
        source=Tool.ADMAPPER,
        manual=f"evil-winrm -i {cred.host} -u '{cred.domain}\\{cred.username}' -H <hash>",
    )

    target_arch: str | None = None
    monitor_log = acl_out = ""

    intel = extract_hijack_intel(loot)

    print_info("post-ex: reading service logs …")
    monitor_log, discovered_log_path = _probe_service_logs(client, intel)
    if not monitor_log:
        monitor_log = _local_monitor_from_loot(
            ws_path / "loot", drop_path=intel.drop_path if intel else ""
        )
        if monitor_log:
            print_ok(
                f"service log (local loot): {len(monitor_log.splitlines())} line(s)",
                source=Tool.ADMAPPER,
            )
    monitor_log = _clean_monitor_log(monitor_log)
    if monitor_log:
        intel = extract_hijack_intel(loot, monitor_log=monitor_log) or intel
        from admapper.postex.hijack_intel import with_discovered_monitor_log_path

        intel = with_discovered_monitor_log_path(intel, discovered_log_path)
    elif not intel:
        intel = extract_hijack_intel(loot)

    com_out = ""
    task_enum_method = ""
    intel_sufficient = _intel_sufficient(
        intel, monitor_log, loot=loot, drop_path=intel.drop_path if intel else ""
    )
    task_filter = None
    if intel:
        if intel.task_name_hint:
            task_filter = intel.task_name_hint
        elif intel.drop_path:
            task_filter = intel.drop_path.rstrip("\\/").split("\\")[-1] or None
        elif intel.com_task_filter:
            task_filter = intel.com_task_filter
    # Loot/log supplies zip+dll paths but not the task Principal — always enumerate.
    if intel_sufficient:
        print_info("DLL-hijack paths from log/loot — enumerating scheduled tasks for run-as principal")
    if task_filter:
        print_info(f"task enum: filter {task_filter!r}")
    try:
        com_out, task_enum_method = _enumerate_scheduled_tasks(client, task_filter)
    except WinRMError as exc:
        msg = f"task enum: {exc}"
        result.errors.append(msg)
        print_warning(msg)

    if intel is None:
        intel = extract_hijack_intel(loot, monitor_log=monitor_log, com_task_output=com_out)
    if intel is None and com_out.strip():
        intel = intel_from_com_tasks(com_out)

    if intel is None:
        acl_scripts: tuple[tuple[str, str], ...] = ()
        if not com_out.strip() and not monitor_log.strip():
            result.errors.append(
                "could not derive drop paths — need loot with zip/dll hints or COM task paths"
            )
            print_warn(
                "no DLL-hijack routes found — need loot with zip/dll or clearer task arguments",
                source=Tool.ADMAPPER,
                manual="admapper postex scan -w <workspace>",
            )
            _write_scan_payload(
                ws_path,
                cred=cred,
                domain=domain,
                result=result,
                task_enum_method=task_enum_method,
                com_out=com_out,
                nxc_raw=getattr(client, "last_raw_output", ""),
            )
            return result
        print_warn(
            "sin rutas DLL-hijack en loot — analizando tareas remotas en vivo",
            source=Tool.ADMAPPER,
            manual="admapper postex scan -w <workspace>",
        )
    else:
        drop_base = intel.drop_path.rstrip("\\") if intel.drop_path else ""
        monitor_candidates = []
        if intel.monitor_log_path:
            monitor_candidates.append(intel.monitor_log_path)
        if drop_base:
            for suffix in (r"\Logs\monitor.log", r"\Logs\app.log", r"\Logs\service.log", r"\Logs\error.log",
                           r"\monitor.log", r"\app.log", r"\service.log"):
                monitor_candidates.append(drop_base + suffix)
        acl_scripts = []
        if not monitor_log.strip():
            acl_scripts.append(("service log", _ps_service_log_candidates(monitor_candidates)))
        # Always check ACL: log presence does not prove the drop path
        # is writable, which is required to land the payload.
        acl_scripts.append(("ACL", _ps_acl(intel.drop_path)))

    for label, script in acl_scripts:
        try:
            proc = client.execute(script, shell="powershell")
            text = (proc.stdout or "").strip()
            if label == "service log":
                monitor_log = text
            else:
                acl_out = text
            if text and label != "ACL":
                print_success(f"{label}: {len(text.splitlines())} line(s)")
        except WinRMError as exc:
            msg = f"{label}: {exc}"
            result.errors.append(msg)
            print_warning(msg)

    target_arch = infer_arch_from_monitor_log(monitor_log) or target_arch
    if not target_arch and com_out:
        for line in com_out.splitlines():
            if "|" not in line:
                continue
            parts = line.split("|", 3)
            exe = parts[2].strip().strip('"') if len(parts) > 2 else ""
            if not exe.lower().endswith(".exe"):
                continue
            try:
                proc = client.execute(ps_read_pe_arch_script(exe), shell="powershell")
                target_arch = normalize_arch((proc.stdout or "").strip())
                if target_arch:
                    print_info(f"target PE arch: {target_arch} ({exe})")
                    break
            except WinRMError:
                pass

    result.analysis = analyze_task_hijack(
        loot=loot,
        com_task_output=com_out,
        monitor_log=monitor_log,
        acl_output=acl_out,
        target_arch=target_arch,
        discovered_monitor_log_path=discovered_log_path or None,
    )

    out_path = _write_scan_payload(
        ws_path,
        cred=cred,
        domain=domain,
        result=result,
        task_enum_method=task_enum_method,
        com_out=com_out,
        nxc_raw=getattr(client, "last_raw_output", ""),
    )

    if result.analysis.findings:
        f = result.analysis.findings[0]
        print_success(
            f"DLL hijack: task={f.task_name} run_as={f.run_as_user} "
            f"writable={f.writable} → {f.drop_path}\\{f.payload_zip}"
        )
        if len(result.analysis.findings) > 1:
            print_info(
                f"+ {len(result.analysis.findings) - 1} additional task(s) in postex_scan.json"
            )
    else:
        print_warning("no DLL hijack finding — check postex_scan.json")

    print_success(f"remote scan saved → {out_path}")
    return result
