from pathlib import Path

from admapper.core.install_check import collect_install_issues, collect_tool_matrix
from admapper.core.paths import find_repo_root, is_package_source_dir, resolve_workspaces_root


def test_find_repo_root_from_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='admapper'\n", encoding="utf-8")
    pkg = tmp_path / "admapper"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    assert find_repo_root(tmp_path / "admapper") == tmp_path


def test_is_package_source_dir_detects_inner_package(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    inner = tmp_path / "admapper"
    inner.mkdir()
    (inner / "__init__.py").write_text("", encoding="utf-8")
    (inner / "cli").mkdir()
    (inner / "core").mkdir()
    assert is_package_source_dir(inner)
    assert not is_package_source_dir(tmp_path)


def test_wrong_cwd_issue_when_inside_package(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("admapper.core.paths.user_config_dir", lambda: tmp_path / ".admapper")
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    inner = tmp_path / "admapper"
    inner.mkdir()
    (inner / "__init__.py").write_text("", encoding="utf-8")
    (inner / "cli").mkdir()
    (inner / "core").mkdir()
    monkeypatch.chdir(inner)
    issues = collect_install_issues()
    codes = {i.code for i in issues}
    assert "wrong_cwd" in codes


def test_resolve_uses_user_home_not_repo_subdirectory(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("admapper.core.paths.user_config_dir", lambda: tmp_path / ".admapper")
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    pkg = tmp_path / "admapper"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "workspaces").mkdir()
    monkeypatch.chdir(pkg)
    root = resolve_workspaces_root()
    assert root == tmp_path / ".admapper" / "workspaces"


def test_collect_tool_matrix_has_required_tools() -> None:
    rows = collect_tool_matrix()
    tools = {row["tool"] for row in rows}
    assert "nxc" in tools
    assert "impacket-getTGT" in tools
    assert "faketime" in tools
    assert "ntpdate" in tools
    assert "certipy" in tools
    for row in rows:
        assert row["installed"] in {"yes", "no"}
        assert row["required_for"]
