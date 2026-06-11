from __future__ import annotations

from pathlib import Path

from admapper.core.compatibility import distribution_summary, feature_matrix
from admapper.core.output import print_info, print_table, print_warning
from admapper.core.platform import ensure_user_dirs, inspect_tools, user_config_dir

_TOOL_TIERS = {
    "impacket": "recon",
    "kerbrute": "external",
    "nxc": "external",
    "hashcat": "external",
    "john": "external",
}


def print_platform_report() -> None:
    """Show OS, distribution model, feature tiers, and optional tools."""
    from admapper.core.install_check import collect_install_issues
    from admapper.core.paths import find_repo_root, is_package_source_dir

    ensure_user_dirs()

    cwd_issues = [
        i for i in collect_install_issues()
        if i.severity in {"error", "warning"}
        and i.code in {"wrong_cwd", "repo_not_found", "workspaces_missing", "cwd_not_repo"}
    ]
    if cwd_issues:
        for issue in cwd_issues:
            if issue.severity == "error":
                print_warning(issue.message)
            else:
                print_warning(issue.message)
            if issue.fix:
                print_info(f"  fix: {issue.fix}")

    repo = find_repo_root()
    if repo and not is_package_source_dir(Path.cwd()):
        print_info(f"Repo root: {repo}")

    summary = distribution_summary()
    print_info(f"Platform: {summary['platform']}")
    print_info(f"Python package: {summary['package']}")
    print_info(f"Entry point: {summary['entrypoint']}")
    print_info(f"Config: {user_config_dir()}")
    print_info(f"Wordlists: {user_config_dir() / 'wordlists'}")

    feature_rows = [
        [item.command, item.tier.value, item.level.value, item.runtime]
        for item in feature_matrix()
    ]
    print_table(
        "Feature compatibility",
        ["command", "tier", "level", "runtime"],
        feature_rows,
    )

    tool_rows = [
        [
            tool.name,
            "yes" if tool.available else "no",
            tool.path or "-",
            _TOOL_TIERS.get(tool.name, "external"),
        ]
        for tool in inspect_tools()
    ]
    print_table("Optional tools", ["tool", "found", "path", "tier"], tool_rows)

    missing = [t for t in inspect_tools() if not t.available]
    if missing:
        print_warning("missing tools are optional — tier CORE features work without them")
        for tool in missing:
            tier = _TOOL_TIERS.get(tool.name, "external")
            print_info(f"  {tool.name} [{tier}]: {tool.hint}")
