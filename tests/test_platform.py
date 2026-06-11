from pathlib import Path
from unittest.mock import patch

from admapper.core.platform import (
    default_wordlist_paths,
    extra_tool_dirs,
    is_macos,
    is_windows,
    platform_label,
    resolve_executable,
    resolve_impacket_script,
    tool_install_hint,
    user_config_dir,
)


def test_default_wordlist_paths_include_user_override() -> None:
    paths = default_wordlist_paths()
    assert paths[0] == user_config_dir() / "wordlists" / "rockyou.txt"
    assert paths[0].name == "rockyou.txt"


def test_macos_wordlist_paths_when_darwin() -> None:
    if not is_macos():
        return
    paths = [str(p) for p in default_wordlist_paths()]
    assert any("/opt/homebrew/share" in p or "/usr/local/share" in p for p in paths)


def test_windows_wordlist_paths_when_win32() -> None:
    if not is_windows():
        return
    paths = [str(p) for p in default_wordlist_paths()]
    assert any("wordlists" in p for p in paths)


def test_platform_label_mapping() -> None:
    with patch("admapper.core.platform.sys.platform", "darwin"):
        assert platform_label() == "macOS"
    with patch("admapper.core.platform.sys.platform", "win32"):
        assert platform_label() == "Windows"


def test_resolve_executable_checks_extra_dirs(tmp_path: Path) -> None:
    tool_dir = tmp_path / "bin"
    tool_dir.mkdir()
    binary = tool_dir / "fakekerbrute"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)

    with patch("admapper.core.platform.extra_tool_dirs", return_value=[tool_dir]):
        with patch("shutil.which", return_value=None):
            assert resolve_executable(["fakekerbrute"]) == str(binary)


def test_resolve_impacket_script_python_fallback() -> None:
    with patch("admapper.core.platform.resolve_executable", return_value=None):
        cmd = resolve_impacket_script("GetNPUsers")
    assert cmd[0]
    assert "impacket.examples.GetNPUsers" in " ".join(cmd)


def test_tool_install_hint_macos() -> None:
    with patch("admapper.core.platform.is_macos", return_value=True):
        with patch("admapper.core.platform.is_windows", return_value=False):
            assert "brew" in tool_install_hint("hashcat")


def test_tool_install_hint_windows() -> None:
    with (
        patch("admapper.core.platform.is_windows", return_value=True),
        patch("admapper.core.platform.is_macos", return_value=False),
    ):
        assert "PATH" in tool_install_hint("kerbrute")


def test_extra_tool_dirs_includes_venv_parent() -> None:
    dirs = extra_tool_dirs()
    assert dirs
