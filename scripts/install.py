#!/usr/bin/env python3
"""ADMapper cross-platform installer.

Usage:
    python3 scripts/install.py              # pipx global install
    python3 scripts/install.py --venv       # local .venv install
    python3 scripts/install.py --dev        # local .venv + dev extras
    python3 scripts/install.py --uninstall  # remove admapper and .venv
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_NAME = "admapper"
MIN_PYTHON = (3, 11)


def ok(msg: str) -> None:
    print(f"[+] {msg}")


def info(msg: str) -> None:
    print(f"[*] {msg}")


def warn(msg: str) -> None:
    print(f"[!] {msg}")


def die(msg: str) -> None:
    print(f"[-] {msg}")
    raise SystemExit(1)


def repo_root() -> Path:
    script = Path(__file__).resolve().parent
    candidates = [script.parent, Path.cwd()]
    for candidate in candidates:
        if (candidate / "pyproject.toml").is_file() and (candidate / "admapper" / "cli" / "main.py").is_file():
            return candidate
    # One-liner mode: clone repo
    if shutil.which("git"):
        info("Not in repo — cloning from GitHub...")
        tmp = Path(tempfile.gettempdir()) / f"admapper-install-{os.getpid()}"
        if tmp.exists():
            shutil.rmtree(tmp)
        subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/0x15k/admapper.git", str(tmp)],
            check=True,
        )
        return tmp
    die("Not in admapper repo and git is not available")


def find_python() -> tuple[str, tuple[int, int]]:
    candidates = ["python3.13", "python3.12", "python3.11", "python3"]
    for candidate in candidates:
        exe = shutil.which(candidate)
        if not exe:
            continue
        try:
            out = subprocess.run(
                [exe, "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            major, minor = map(int, out.split(".")[:2])
            if (major, minor) >= MIN_PYTHON:
                return exe, (major, minor)
        except Exception:
            continue
    die(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ not found. Install from https://python.org/downloads")


def detect_os() -> tuple[str, bool]:
    system = platform.system().lower()
    is_kali = False
    if system == "linux" and Path("/etc/os-release").is_file():
        try:
            text = Path("/etc/os-release").read_text(encoding="utf-8").lower()
            is_kali = "kali" in text or "parrot" in text
        except Exception:
            pass
    if system.startswith("cygwin") or system.startswith("mingw") or system.startswith("msys"):
        system = "windows"
    return system, is_kali


def ensure_repo(root: Path) -> None:
    missing = []
    if not (root / "pyproject.toml").is_file():
        missing.append("pyproject.toml")
    if not (root / "admapper").is_dir():
        missing.append("admapper/")
    if not (root / "admapper" / "cli" / "main.py").is_file():
        missing.append("admapper/cli/main.py")
    if missing:
        die(f"Incomplete repo at {root} — missing: {', '.join(missing)}")
    (root / "workspaces").mkdir(exist_ok=True)
    ok(f"Repo: {root}")


def run(*cmd: str, check: bool = True, cwd: Path | None = None, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), check=check, cwd=cwd, **kwargs)


def run_capture(*cmd: str, cwd: Path | None = None, **kwargs) -> str:
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        check=True,
        cwd=cwd,
        **kwargs,
    ).stdout.strip()


def ensure_system_packages(system: str, is_kali: bool) -> None:
    if system != "linux":
        return
    apt = shutil.which("apt-get")
    if not apt:
        warn("apt-get not found — skipping system package install")
        return
    packages = ["python3-venv", "python3-pip", "krb5-user", "libfaketime"]
    info(f"Installing system packages: {', '.join(packages)}")
    try:
        run("sudo", "apt-get", "update", "-qq")
        run("sudo", "apt-get", "install", "-y", *packages)
        ok("System packages ready")
    except Exception as exc:
        warn(f"System package install failed: {exc}")


def ensure_pipx(python: str, system: str, is_kali: bool) -> str:
    if shutil.which("pipx"):
        ok("pipx found")
        return shutil.which("pipx") or "pipx"

    info("Installing pipx...")
    try:
        if system == "darwin" and shutil.which("brew"):
            run("brew", "install", "pipx", check=False)
        elif system == "linux" and is_kali and shutil.which("apt-get"):
            run("sudo", "apt", "install", "-y", "pipx", check=False)
        else:
            run(python, "-m", "pip", "install", "--user", "pipx", check=False)
    except Exception:
        run(python, "-m", "pip", "install", "--user", "--break-system-packages", "pipx", check=False)

    refresh_path(python, system)
    pipx = shutil.which("pipx")
    if not pipx:
        die("pipx installed but not in PATH. Restart terminal and retry.")
    return pipx


def refresh_path(python: str, system: str) -> None:
    home = Path.home()
    os.environ["PATH"] = f"{home / '.local' / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"
    if system == "darwin":
        try:
            user_base = subprocess.run(
                [python, "-m", "site", "--user-base"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            if user_base and Path(user_base).is_dir():
                os.environ["PATH"] = f"{Path(user_base) / 'bin'}{os.pathsep}{os.environ['PATH']}"
        except Exception:
            pass


def install_pipx(root: Path, pipx: str, extra: str, force: bool) -> None:
    try:
        installed_short = subprocess.run(
            [pipx, "list", "--short"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        already_installed = any(line.startswith("admapper ") for line in installed_short.splitlines())
    except Exception:
        already_installed = False

    if already_installed and not force:
        info("admapper already installed via pipx — force reinstalling...")
        run(pipx, "install", "--editable", f".[{extra}]", "--force", cwd=root)
    else:
        args = [pipx, "install", "--editable", f".[{extra}]"]
        if force:
            args.append("--force")
        run(*args, cwd=root)

    try:
        run(pipx, "ensurepath", check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    ok("admapper installed globally")


def install_venv(root: Path, python: str, extra: str, system: str, is_kali: bool) -> None:
    venv = root / ".venv"
    info(f"Creating venv at {venv}")
    try:
        run(python, "-m", "venv", str(venv))
    except Exception as exc:
        if system == "linux" and is_kali and shutil.which("apt-get"):
            warn("venv failed — installing python3-venv")
            run("sudo", "apt", "install", "-y", "python3-venv")
            run(python, "-m", "venv", str(venv))
        else:
            die(f"venv creation failed: {exc}")

    pip = venv / "bin" / "pip"
    if system == "windows":
        pip = venv / "Scripts" / "pip.exe"
    run(str(pip), "install", "-U", "pip", "-q")
    run(str(pip), "install", "-e", f".[{extra}]", cwd=root)
    ok(f"admapper installed in {venv}")
    print(f"[*] Activate:  {venv / 'bin' / 'activate'}")
    print(f"[*] Then run:  admapper --help")


def uninstall(root: Path) -> None:
    info("Removing admapper...")
    if shutil.which("pipx"):
        subprocess.run([shutil.which("pipx") or "pipx", "uninstall", "admapper"], check=False)
    venv = root / ".venv"
    if venv.is_dir():
        shutil.rmtree(venv)
        ok("Removed .venv")
    ok("Uninstall complete")


def install_companion_tools(system: str, is_kali: bool, python_exe: str, force: bool = False) -> None:
    print()
    info("Installing/verifying companion tools...")

    # 1. Install pipx tools
    pipx = shutil.which("pipx")
    if not pipx:
        pipx = ensure_pipx(python_exe, system, is_kali)

    pipx_tools = {
        "certipy": "certipy-ad",
        "pywhisker": "pywhisker",
        "nxc": "netexec",
    }

    for bin_name, package in pipx_tools.items():
        if shutil.which(bin_name) and not force:
            ok(f"Companion (Python): {package} is already installed ({shutil.which(bin_name)})")
        else:
            action_str = "Reinstalling" if force and shutil.which(bin_name) else "Installing"
            info(f"{action_str} {package} via pipx...")
            try:
                args = [pipx, "install", package]
                if force:
                    args.append("--force")
                run(*args)
                ok(f"Installed/Reinstalled {package}")
            except Exception as exc:
                warn(f"Failed to install {package}: {exc}")

    # 2. Install system tools
    if system == "darwin":
        brew = shutil.which("brew")
        if not brew:
            warn("brew not found — cannot install native companion tools (hashcat, john, libfaketime)")
            return

        brew_tools = {
            "hashcat": "hashcat",
            "john": "john-jumbo",
            "faketime": "libfaketime",
        }
        for bin_name, formula in brew_tools.items():
            if shutil.which(bin_name) and not force:
                ok(f"Companion (System): {formula} is already installed ({shutil.which(bin_name)})")
            else:
                action_str = "Reinstalling" if force and shutil.which(bin_name) else "Installing"
                info(f"{action_str} {formula} via Homebrew...")
                try:
                    cmd = [brew, "reinstall" if force else "install", formula]
                    run(*cmd)
                    ok(f"Installed/Reinstalled {formula}")
                except Exception as exc:
                    warn(f"Failed to install {formula}: {exc}")

    elif system == "linux":
        apt = shutil.which("apt-get")
        if not apt:
            warn("apt-get not found — cannot install native companion tools (hashcat, john)")
            return

        apt_tools = {
            "hashcat": "hashcat",
            "john": "john",
        }
        for bin_name, package in apt_tools.items():
            if shutil.which(bin_name) and not force:
                ok(f"Companion (System): {package} is already installed ({shutil.which(bin_name)})")
            else:
                action_str = "Reinstalling" if force and shutil.which(bin_name) else "Installing"
                info(f"{action_str} {package} via apt-get...")
                try:
                    cmd = ["sudo", "apt-get", "install", "-y"]
                    if force:
                        cmd.append("--reinstall")
                    cmd.append(package)
                    run(*cmd)
                    ok(f"Installed/Reinstalled {package}")
                except Exception as exc:
                    warn(f"Failed to install {package}: {exc}")


def post_install(system: str) -> None:
    print()
    print("Quick start:")
    print("  admapper run -H <DC_IP> -u <user> -p '<pass>'")
    print("  admapper doctor    # verify installation health")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="ADMapper cross-platform installer")
    parser.add_argument("--venv", action="store_true", help="Local .venv install")
    parser.add_argument("--dev", action="store_true", help="Local .venv + dev extras")
    parser.add_argument("--force", action="store_true", help="Force reinstall")
    parser.add_argument("--uninstall", action="store_true", help="Remove admapper")
    args = parser.parse_args()

    extra = "full" if not args.dev else "dev"

    if args.uninstall:
        uninstall(repo_root())
        return

    python, version = find_python()
    ok(f"Python {version[0]}.{version[1]} ({python})")

    system, is_kali = detect_os()
    detail = f"{platform.machine()}"
    if is_kali:
        detail += ", Kali/Parrot"
    ok(f"Platform: {system} ({detail})")

    root = repo_root()
    ensure_repo(root)
    print()

    if args.venv or args.dev:
        if system == "linux":
            ensure_system_packages(system, is_kali)
        install_venv(root, python, extra, system, is_kali)
    else:
        if system == "linux":
            ensure_system_packages(system, is_kali)
        pipx = ensure_pipx(python, system, is_kali)
        install_pipx(root, pipx, extra, args.force)

    install_companion_tools(system, is_kali, python, force=args.force)

    post_install(system)


if __name__ == "__main__":
    main()
