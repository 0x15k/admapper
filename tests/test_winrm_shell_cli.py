from __future__ import annotations

import pytest
import typer

from admapper.winrm.shell_cli import _warn_protected_user_winrm


def test_warn_protected_user_winrm_uses_dc_ip(monkeypatch, capsys) -> None:
    """Regression: the warning path referenced an undefined `dc` (NameError)
    instead of the `dc_ip` parameter. It must complete and exit cleanly."""
    monkeypatch.setattr(
        "admapper.winrm.shell_cli._machine_hash_hint",
        lambda dc_ip: None,
    )
    with pytest.raises(typer.Exit) as exc_info:
        _warn_protected_user_winrm(
            domain="lab.htb",
            username="svc_recovery",
            dc_ip="10.129.20.182",
        )
    assert exc_info.value.exit_code == 1


def test_warn_protected_user_winrm_passes_dc_ip_to_hint(monkeypatch) -> None:
    """The DC IP given to the command must be forwarded to the hash hint lookup."""
    received: dict[str, str] = {}

    def fake_hint(dc_ip: str):
        received["dc_ip"] = dc_ip
        return None

    monkeypatch.setattr("admapper.winrm.shell_cli._machine_hash_hint", fake_hint)
    with pytest.raises(typer.Exit):
        _warn_protected_user_winrm(
            domain="lab.htb",
            username="svc_recovery",
            dc_ip="10.129.20.182",
        )
    assert received["dc_ip"] == "10.129.20.182"
