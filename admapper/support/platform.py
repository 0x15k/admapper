from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_PLATFORM_LABELS = {
    "darwin": "macOS",
    "linux": "Linux",
    "win32": "Windows",
}


def system_name() -> str:
    """Return the Python sys.platform value (darwin, linux, win32, ...)."""
    return sys.platform


def platform_label() -> str:
    """Human-readable OS name."""
    return _PLATFORM_LABELS.get(sys.platform, sys.platform)


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_windows() -> bool:
    return sys.platform == "win32"


def user_config_dir() -> Path:
    """Cross-platform config directory (~/.admapper or %USERPROFILE%\\.admapper)."""
    return Path.home() / ".admapper"


def ensure_user_dirs() -> dict[str, Path]:
    """Create standard ADMapper directories under the user config root."""
    dirs = {
        "config": user_config_dir(),
        "wordlists": user_config_dir() / "wordlists",
        "workspaces": user_config_dir() / "workspaces",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def _venv_tool_dirs() -> list[Path]:
    """Bin/Scripts directory of the active Python interpreter (venv-aware)."""
    scripts = Path(sys.executable).resolve().parent
    return [scripts] if scripts.is_dir() else []


def extra_tool_dirs() -> list[Path]:
    """Common install locations not always present in PATH."""
    home = Path.home()
    dirs = list(_venv_tool_dirs())

    if is_macos():
        dirs.extend(
            [
                Path("/opt/homebrew/bin"),
                Path("/opt/homebrew/sbin"),
                Path("/usr/local/bin"),
                Path("/usr/local/sbin"),
            ]
        )
    elif is_windows():
        local_app = os.environ.get("LOCALAPPDATA", "")
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        dirs.extend(
            [
                home / "go" / "bin",
                Path(local_app) / "Programs" / "Python",
                Path(program_files) / "Python311" / "Scripts",
                Path(program_files) / "Python312" / "Scripts",
                Path(program_files) / "Python313" / "Scripts",
                Path(program_files) / "hashcat",
                Path(program_files_x86) / "hashcat",
            ]
        )

    return [path for path in dirs if path.is_dir()]


def resolve_executable(names: list[str]) -> str | None:
    """Locate a CLI tool by name across PATH and known install directories."""
    for name in names:
        found = shutil.which(name)
        if found:
            return found

    suffixes = (".exe", ".cmd", ".bat") if is_windows() else ()
    for directory in extra_tool_dirs():
        for name in names:
            candidates = [directory / name]
            candidates.extend(directory / f"{name}{suffix}" for suffix in suffixes)
            for candidate in candidates:
                if candidate.is_file():
                    return str(candidate)
    return None


def resolve_kerbrute() -> str | None:
    return resolve_executable(["kerbrute"])


def resolve_certipy() -> str | None:
    return resolve_executable(["certipy", "certipy-ad"])


def resolve_nxc() -> str | None:
    return resolve_executable(["nxc", "netexec"])


def resolve_faketime() -> str | None:
    """libfaketime installs the faketime binary (brew install libfaketime)."""
    return resolve_executable(["faketime"])


# Applied to subprocess tools (nxc, impacket CLI) when KDC clock skew is detected/set.
_clock_skew: str | None = None


def get_clock_skew() -> str | None:
    return _clock_skew


def set_clock_skew(skew: str | None) -> None:
    global _clock_skew
    _clock_skew = skew.strip() if skew else None


def wrap_command_with_clock_skew(cmd: list[str], *, clock_skew: str | None = None) -> list[str]:
    skew = clock_skew or _clock_skew
    if not skew:
        return cmd
    faketime = resolve_faketime()
    if not faketime:
        return cmd
    return [faketime, "-f", skew, *cmd]


def resolve_hashcat() -> str | None:
    return resolve_executable(["hashcat"])


def resolve_john() -> str | None:
    return resolve_executable(["john"])


def resolve_impacket_script(script: str) -> list[str]:
    """
    Return argv prefix for an Impacket example script.

    Tries impacket-<Script>, <Script>.py, then python -m impacket.examples.<Script>.
    """
    dashed = f"impacket-{script}"
    for name in (dashed, script, f"{script}.py"):
        found = resolve_executable([name])
        if found:
            return [found]
    return [sys.executable, "-m", f"impacket.examples.{script}"]


def default_wordlist_paths() -> list[Path]:
    """
    Common rockyou/seclists locations across macOS, Linux, and Windows.

    Priority: ~/.admapper/wordlists/ first, then OS-specific system paths.
    """
    home = Path.home()
    paths = [
        home / ".admapper" / "wordlists" / "rockyou.txt",
        home / "wordlists" / "rockyou.txt",
    ]

    if is_macos():
        paths.extend(
            [
                Path("/opt/homebrew/share/seclists/Passwords/Leaked-Databases/rockyou.txt"),
                Path("/opt/homebrew/share/wordlists/rockyou.txt"),
                Path("/usr/local/share/seclists/Passwords/Leaked-Databases/rockyou.txt"),
                Path("/usr/local/share/wordlists/rockyou.txt"),
            ]
        )
    elif is_linux():
        paths.extend(
            [
                Path("/usr/share/wordlists/rockyou.txt"),
                Path("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"),
            ]
        )
    elif is_windows():
        local_app = os.environ.get("LOCALAPPDATA", "")
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        paths.extend(
            [
                Path(local_app) / "wordlists" / "rockyou.txt",
                Path(program_files) / "wordlists" / "rockyou.txt",
                Path(r"C:\wordlists\rockyou.txt"),
            ]
        )

    return paths


def subprocess_run_kwargs() -> dict:
    """Extra keyword arguments for subprocess.run on the current platform."""
    if not is_windows():
        return {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if flags:
        return {"creationflags": flags}
    return {}


def run_command(
    cmd: list[str],
    *,
    timeout: int | None = None,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
    clock_skew: str | None = None,
    use_clock_skew: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an external command with cross-platform subprocess defaults."""
    if use_clock_skew:
        cmd = wrap_command_with_clock_skew(cmd, clock_skew=clock_skew)
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    return subprocess.run(
        cmd,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        check=check,
        env=run_env,
        **subprocess_run_kwargs(),
    )


def mit_krb5_install_hint() -> str:
    """Platform-specific install hint for MIT Kerberos CLI (kinit, kvno)."""
    if is_macos():
        return "brew install krb5"
    if is_linux():
        return "sudo apt install krb5-user"
    return "install MIT Kerberos (kinit/kvno on PATH)"


def resolve_mit_krb5_bin(name: str) -> str | None:
    """Locate MIT krb5 binaries — Homebrew on macOS, PATH elsewhere (e.g. krb5-user on Kali)."""
    if is_macos():
        for prefix in ("/opt/homebrew/opt/krb5/bin", "/usr/local/opt/krb5/bin"):
            candidate = Path(prefix) / name
            if candidate.is_file():
                return str(candidate)
    return resolve_executable([name])


def tool_install_hint(tool: str) -> str:
    """Short platform-specific install suggestion."""
    if is_windows():
        hints = {
            "kerbrute": "download kerbrute.exe and add to PATH",
            "hashcat": "install hashcat binaries and add to PATH",
            "john": "install John the Ripper and add john.exe to PATH",
            "nxc": "pip install netexec  (Scripts folder must be on PATH)",
            "impacket": "pip install -e \".[recon]\"  (activate .venv first)",
        }
        return hints.get(tool, "add the tool to PATH — see docs/PLATFORMS.md")
    if is_macos():
        hints = {
            "kerbrute": "brew install kerbrute  # or go install …",
            "hashcat": "brew install hashcat",
            "john": "brew install john-jumbo",
            "nxc": (
                "brew install rust python@3.13 && "
                "pipx install --python python3.13 git+https://github.com/Pennyw0rth/NetExec"
            ),
            "impacket": "pip install -e '.[recon]'",
            "faketime": "brew install libfaketime",
        }
        return hints.get(tool, f"brew install {tool} or check PATH")
    hints = {
        "kerbrute": "go install … or download release binary",
        "hashcat": "apt install hashcat",
        "john": "apt install john",
        "nxc": "pip install netexec",
        "impacket": "pip install -e '.[recon]'",
        "faketime": "apt install faketime  # or libfaketime",
        "krb5": mit_krb5_install_hint(),
    }
    return hints.get(tool, f"apt install {tool} or pip install impacket")


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: str | None
    hint: str


def _impacket_status() -> tuple[bool, str | None]:
    try:
        import impacket  # noqa: F401

        module_path = getattr(impacket, "__file__", None)
        return True, str(module_path) if module_path else "python package"
    except ImportError:
        script = resolve_executable(["impacket-GetNPUsers", "GetNPUsers.py"])
        return script is not None, script


def inspect_tools() -> list[ToolStatus]:
    """Report availability of optional external tools on this machine."""
    impacket_ok, impacket_path = _impacket_status()
    specs: list[tuple[str, bool, str | None]] = [
        ("impacket", impacket_ok, impacket_path),
        ("kerbrute", bool(resolve_kerbrute()), resolve_kerbrute()),
        ("nxc", bool(resolve_nxc()), resolve_nxc()),
        ("hashcat", bool(resolve_hashcat()), resolve_hashcat()),
        ("john", bool(resolve_john()), resolve_john()),
        ("faketime", bool(resolve_faketime()), resolve_faketime()),
    ]
    return [
        ToolStatus(
            name=name,
            available=available,
            path=path,
            hint=tool_install_hint(name),
        )
        for name, available, path in specs
    ]
