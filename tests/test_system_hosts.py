from __future__ import annotations

from pathlib import Path

from admapper.core.system_hosts import (
    HostsSyncStatus,
    ensure_system_hosts_entry,
    format_hosts_sync_message,
)


def test_add_hosts_entry(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    result = ensure_system_hosts_entry(
        "192.168.10.130",
        "dc01.target.example",
        use_sudo=False,
        hosts_path=hosts,
    )
    assert result.status == HostsSyncStatus.ADDED
    text = hosts.read_text(encoding="utf-8")
    assert "192.168.10.130  dc01.target.example" in text
    assert "# admapper" in text


def test_update_hosts_entry_on_target_respawn(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "127.0.0.1 localhost\n192.168.10.182  dc01.target.example\n",
        encoding="utf-8",
    )
    result = ensure_system_hosts_entry(
        "192.168.10.130",
        "dc01.target.example",
        use_sudo=False,
        hosts_path=hosts,
    )
    assert result.status == HostsSyncStatus.UPDATED
    assert result.previous_ip == "192.168.10.182"
    text = hosts.read_text(encoding="utf-8")
    assert "192.168.10.130  dc01.target.example" in text
    assert "192.168.10.182" not in text


def test_present_hosts_entry_is_idempotent(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("192.168.10.130  dc01.target.example\n", encoding="utf-8")
    before = hosts.read_text(encoding="utf-8")
    result = ensure_system_hosts_entry(
        "192.168.10.130",
        "dc01.target.example",
        use_sudo=False,
        hosts_path=hosts,
    )
    assert result.status == HostsSyncStatus.PRESENT
    assert hosts.read_text(encoding="utf-8") == before


def test_format_hosts_sync_message_updated() -> None:
    from admapper.core.system_hosts import HostsSyncResult

    msg = format_hosts_sync_message(
        HostsSyncResult(
            HostsSyncStatus.UPDATED,
            "192.168.10.130",
            "dc01.target.example",
            previous_ip="192.168.10.182",
        )
    )
    assert "192.168.10.182" in msg
    assert "192.168.10.130" in msg
