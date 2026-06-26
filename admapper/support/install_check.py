from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

from admapper.support.paths import (
    WORKSPACES_ENV_VAR,
    default_user_workspaces_root,
    find_repo_root,
    is_package_source_dir,
    legacy_repo_workspaces,
    resolve_workspaces_root,
)
from admapper.support.platform import inspect_tools, platform_label

_PYTHON_CORE = (
    ("typer", "typer", "pip install -e '.[full]'"),
    ("rich", "rich", "pip install -e '.[full]'"),
    ("ldap3", "ldap3", "pip install -e '.[full]'"),
    ("dns", "dnspython", "pip install -e '.[full]'"),
)

_PYTHON_RECON = (
    ("impacket", "impacket", "pip install -e '.[full]'  # incluye impacket"),
    ("pypsrp", "pypsrp", "pip install -e '.[full]'"),
)

_REPO_MARKERS = (
    "pyproject.toml",
    "admapper/__init__.py",
    "admapper/cli/main.py",
    "scripts/install.sh",
    "workspaces",
)


@dataclass(frozen=True)
class InstallIssue:
    severity: str  # error | warning | info
    code: str
    message: str
    fix: str | None = None


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def collect_tool_matrix() -> list[dict[str, str]]:
    """AdStrike Tool Checker (#58) — external CLI matrix for doctor."""
    from admapper.support.platform import (
        resolve_certipy,
        resolve_executable,
        resolve_faketime,
        resolve_impacket_script,
        resolve_nxc,
    )

    def _row(
        tool: str,
        path: str | None,
        *,
        required_for: str,
        optional: bool = False,
    ) -> dict[str, str]:
        return {
            "tool": tool,
            "installed": "yes" if path else "no",
            "path": path or "-",
            "required_for": required_for + (" (optional)" if optional else ""),
        }

    ntpdate = resolve_executable(["ntpdate", "ntpsec-ntpdate"])
    get_tgt = resolve_impacket_script("getTGT")
    get_tgt_path = get_tgt[0] if get_tgt else None

    return [
        _row("nxc", resolve_nxc(), required_for="SMB/LDAP spray, loot"),
        _row("impacket-getTGT", get_tgt_path, required_for="Kerberos TGT, WinRM"),
        _row("faketime", resolve_faketime(), required_for="clock skew / Protected Users"),
        _row("ntpdate", ntpdate, required_for="DC clock sync"),
        _row(
            "evil-winrm",
            resolve_executable(["evil-winrm"]),
            required_for="WinRM shell",
            optional=True,
        ),
        _row(
            "bloodhound-python",
            resolve_executable(["bloodhound-python", "bloodhound"]),
            required_for="BloodHound collection",
            optional=True,
        ),
        _row("certipy", resolve_certipy(), required_for="AD CS ESC exploitation", optional=True),
    ]


def collect_install_issues(*, cwd: Path | None = None) -> list[InstallIssue]:
    """Validate repo layout, cwd, workspaces, and Python dependencies."""
    issues: list[InstallIssue] = []
    here = (cwd or Path.cwd()).resolve()
    repo = find_repo_root(here)

    if is_package_source_dir(here):
        parent = here.parent
        fix = f"cd {parent}" if (parent / "pyproject.toml").is_file() else "cd <repo-root>"
        issues.append(
            InstallIssue(
                "error",
                "wrong_cwd",
                f"Current directory is the Python package ({here}), not the repo root.",
                fix,
            )
        )

    if repo is None:
        issues.append(
            InstallIssue(
                "warning",
                "repo_not_found",
                "Repo root not found (pyproject.toml + admapper/).",
                "cd /path/to/repo  or  pipx install --editable /path/to/repo/.[full]",
            )
        )
    else:
        issues.append(
            InstallIssue(
                "info",
                "repo_root",
                f"Repo root: {repo}",
                None,
            )
        )
        for marker in _REPO_MARKERS:
            path = repo / marker
            if not path.exists():
                issues.append(
                    InstallIssue(
                        "warning",
                        f"missing_{marker.replace('/', '_')}",
                        f"Missing from repo: {marker}",
                        f"Mount or copy the complete project into {repo}",
                    )
                )
        legacy = legacy_repo_workspaces()
        if legacy:
            count = sum(1 for p in legacy.iterdir() if p.is_dir() and (p / "state.json").is_file())
            if count:
                issues.append(
                    InstallIssue(
                        "info",
                        "legacy_workspaces",
                        f"Legacy workspaces in repo: {legacy} ({count}) — use: admapper -O {legacy}",
                        None,
                    )
                )

    active_root = resolve_workspaces_root()
    count = sum(1 for p in active_root.iterdir() if p.is_dir() and (p / "state.json").is_file())
    issues.append(
        InstallIssue(
            "info",
            "workspaces_root",
            f"Engagement output: {active_root} ({count} workspace(s))",
            f"admapper -O <path>  |  set workspaces <path>  |  env {WORKSPACES_ENV_VAR}",
        )
    )
    if active_root == default_user_workspaces_root():
        issues.append(
            InstallIssue(
                "info",
                "workspaces_default",
                "Default: ~/.admapper/workspaces (outside repo — safe for git)",
                None,
            )
        )

    import shutil
    import sys

    pip_path = shutil.which("pip") or ""
    if (
        sys.prefix == sys.base_prefix
        and pip_path
        and "/.venv/" not in pip_path
        and "venv" not in pip_path
    ):
        issues.append(
            InstallIssue(
                "warning",
                "pip_not_in_venv",
                f"Active pip is not from a venv: {pip_path}",
                "source <repo>/.venv/bin/activate  or  <repo>/.venv/bin/pip install -e '.[full]'",
            )
        )
    if sys.prefix == sys.base_prefix:
        issues.append(
            InstallIssue(
                "info",
                "python_not_venv",
                "Active Python is not a venv — on Kali run: source .venv/bin/activate",
                "./scripts/install.sh --venv",
            )
        )

    for mod, label, fix in _PYTHON_CORE:
        if not _module_available(mod):
            issues.append(
                InstallIssue(
                    "error",
                    f"missing_{mod}",
                    f"Missing core dependency: {label}",
                    fix,
                )
            )

    for mod, label, fix in _PYTHON_RECON:
        if not _module_available(mod):
            issues.append(
                InstallIssue(
                    "warning",
                    f"missing_{mod}",
                    f"Missing recon dependency: {label} (SMB/Kerberos/WinRM limited)",
                    fix,
                )
            )

    missing_tools = [t for t in inspect_tools() if not t.available]
    for tool in missing_tools:
        issues.append(
            InstallIssue(
                "info",
                f"tool_{tool.name}",
                f"External tool not found: {tool.name}",
                tool.hint,
            )
        )

    return issues


def print_doctor_report(*, cwd: Path | None = None) -> int:
    """Print install/layout diagnostics; return non-zero if errors present."""
    from admapper.support.output import (
        print_error,
        print_info,
        print_success,
        print_table,
        print_warning,
    )

    here = (cwd or Path.cwd()).resolve()
    print_info(f"Platform: {platform_label()}")
    print_info(f"Python: {sys.version.split()[0]}")
    print_info(f"cwd: {here}")
    print_info(f"admapper: {Path(__file__).resolve().parents[1]}")

    issues = collect_install_issues(cwd=here)
    rows = [
        [issue.severity, issue.code, issue.message, issue.fix or ""]
        for issue in issues
        if issue.severity != "info" or issue.code in {"repo_root", "workspaces"}
    ]
    print_table("Install check", ["level", "code", "detail", "fix"], rows)

    tool_rows = [
        [row["tool"], row["installed"], row["path"], row["required_for"]]
        for row in collect_tool_matrix()
    ]
    print_table("Tool matrix", ["tool", "installed", "path", "required_for"], tool_rows)

    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]

    if errors:
        print_error(f"{len(errors)} error(s) — fix before using admapper in this environment.")
        for issue in errors:
            if issue.fix:
                print_info(f"  → {issue.fix}")
        return 1

    if warnings:
        print_warning(f"{len(warnings)} warning(s) — admapper may run with limitations.")
    else:
        print_success("Installation and layout OK.")
    return 0
