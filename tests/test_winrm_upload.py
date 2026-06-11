from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from admapper.winrm.client import WinRMClient, WinRMError
from admapper.winrm import upload as upload_mod


def _client(*, nthash: bool = False) -> WinRMClient:
    if nthash:
        return WinRMClient(
            "10.129.20.182",
            domain="logging.htb",
            username="msa_health$",
            ticket_method="nthash",
            nthash="abc123",
            dc_ip="10.129.20.182",
        )
    return WinRMClient(
        "10.0.0.1",
        domain="logging.htb",
        username="user",
        password="pass",
    )


def test_manual_upload_instructions_interactive(tmp_path: Path) -> None:
    local = tmp_path / "Settings_Update.zip"
    local.write_bytes(b"x")
    text = upload_mod.manual_upload_instructions(
        _client(nthash=True),
        local,
        r"C:\ProgramData\UpdateMonitor\Settings_Update.zip",
    )
    assert "interactivo" in text
    assert "upload " in text
    assert "forward slashes" in text or "opción A" in text


def test_upload_evil_winrm_first(tmp_path: Path) -> None:
    local = tmp_path / "Settings_Update.zip"
    local.write_bytes(b"payload")
    client = _client(nthash=True)
    with (
        patch.object(upload_mod, "_upload_via_evil_winrm_builtin", return_value=True) as mock_ew,
        patch.object(upload_mod, "_upload_via_certutil_b64") as mock_b64,
        patch.object(upload_mod, "_upload_base64_chunks") as mock_chunks,
    ):
        upload_mod.upload_file(client, local, r"C:\ProgramData\UpdateMonitor\Settings_Update.zip")
    mock_ew.assert_called_once()
    mock_b64.assert_not_called()
    mock_chunks.assert_not_called()


def test_upload_falls_back_to_certutil(tmp_path: Path) -> None:
    local = tmp_path / "Settings_Update.zip"
    local.write_bytes(b"payload")
    client = _client(nthash=True)
    with (
        patch.object(upload_mod, "_upload_via_evil_winrm_builtin", return_value=False),
        patch.object(upload_mod, "_upload_via_certutil_b64", return_value=True) as mock_b64,
        patch.object(upload_mod, "_upload_base64_chunks") as mock_chunks,
    ):
        upload_mod.upload_file(client, local, r"C:\ProgramData\UpdateMonitor\Settings_Update.zip")
    mock_b64.assert_called_once()
    mock_chunks.assert_not_called()


def test_upload_requires_dir_verification_not_false_positive(tmp_path: Path) -> None:
    local = tmp_path / "Settings_Update.zip"
    local.write_bytes(b"payload")
    client = _client(nthash=True)
    with (
        patch.object(upload_mod, "_upload_via_evil_winrm_builtin", return_value=True),
        patch.object(upload_mod, "_verify_via_evil_winrm_stdin", return_value=False),
        patch.object(upload_mod, "remote_file_ok", return_value=False),
    ):
        upload_mod.upload_file(client, local, r"C:\ProgramData\UpdateMonitor\Settings_Update.zip")


def test_verify_via_stdin_parses_dir(tmp_path: Path) -> None:
    client = _client(nthash=True)
    output = " Settings_Update.zip              1768  06/10/2026"
    with patch.object(upload_mod, "_run_evil_winrm_stdin", return_value=output):
        assert upload_mod._verify_via_evil_winrm_stdin(
            client,
            r"C:\ProgramData\UpdateMonitor\Settings_Update.zip",
            expected_size=1768,
        )


def test_parse_dir_size_ignores_stderr_noise() -> None:
    noisy = (
        "Info: Uploading payload\n"
        "Error: Settings_Update.zip 9999 bytes transferred\n"
        " Settings_Update.zip              1768  06/10/2026"
    )
    assert upload_mod._parse_dir_size(noisy, "Settings_Update.zip") == 1768


def test_quote_local_path_with_spaces(tmp_path: Path) -> None:
    folder = tmp_path / "my payloads"
    folder.mkdir()
    local = folder / "Settings_Update.zip"
    local.write_bytes(b"x")
    quoted = upload_mod._quote_evil_winrm_local(local)
    assert quoted.startswith("'")
    assert "my payloads" in quoted


def test_upload_via_evil_winrm_builtin_direct_then_copy(tmp_path: Path) -> None:
    local = tmp_path / "Settings_Update.zip"
    local.write_bytes(b"payload")
    client = _client(nthash=True)
    remote = r"C:\ProgramData\UpdateMonitor\Settings_Update.zip"
    scripts: list[str] = []

    def fake_stdin(_client, script, **kwargs):  # noqa: ANN001, ARG001
        scripts.append(script)
        return ""

    with (
        patch.object(upload_mod, "resolve_executable", return_value="/usr/bin/evil-winrm"),
        patch.object(upload_mod, "_run_evil_winrm_stdin", side_effect=fake_stdin),
        patch.object(upload_mod, "_verify_via_evil_winrm_stdin", side_effect=[False, True]),
    ):
        assert upload_mod._upload_via_evil_winrm_builtin(
            client, local, remote, expected_size=7
        )

    assert len(scripts) == 2
    assert f"upload {local.resolve()} C:/ProgramData/UpdateMonitor/Settings_Update.zip" in scripts[0]
    assert "dir C:/ProgramData/UpdateMonitor/Settings_Update.zip" in scripts[0]
    assert f"upload {local.resolve()} Settings_Update.zip" in scripts[1]
    assert "copy .\\Settings_Update.zip C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip" in scripts[1]


def test_upload_prints_manual_on_failure(tmp_path: Path) -> None:
    local = tmp_path / "x.bin"
    local.write_bytes(b"1")
    client = _client(nthash=True)
    client.execute = lambda *a, **k: MagicMock(stdout="", returncode=0)  # type: ignore[method-assign]
    with (
        patch.object(upload_mod, "_upload_via_evil_winrm_builtin", return_value=False),
        patch.object(upload_mod, "_upload_via_certutil_b64", return_value=False),
        patch.object(upload_mod, "_upload_base64_chunks", return_value=False),
        pytest.raises(WinRMError, match="upload failed"),
    ):
        upload_mod.upload_file(client, local, r"C:\temp\x.bin")
