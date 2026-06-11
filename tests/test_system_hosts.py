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
        "10.129.245.130",
        "dc01.logging.htb",
        use_sudo=False,
        hosts_path=hosts,
    )
    assert result.status == HostsSyncStatus.ADDED
    text = hosts.read_text(encoding="utf-8")
    assert "10.129.245.130  dc01.logging.htb" in text
    assert "# admapper" in text


def test_update_hosts_entry_on_htb_respawn(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "127.0.0.1 localhost\n10.129.20.182  dc01.logging.htb\n",
        encoding="utf-8",
    )
    result = ensure_system_hosts_entry(
        "10.129.245.130",
        "dc01.logging.htb",
        use_sudo=False,
        hosts_path=hosts,
    )
    assert result.status == HostsSyncStatus.UPDATED
    assert result.previous_ip == "10.129.20.182"
    text = hosts.read_text(encoding="utf-8")
    assert "10.129.245.130  dc01.logging.htb" in text
    assert "10.129.20.182" not in text


def test_present_hosts_entry_is_idempotent(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("10.129.245.130  dc01.logging.htb\n", encoding="utf-8")
    before = hosts.read_text(encoding="utf-8")
    result = ensure_system_hosts_entry(
        "10.129.245.130",
        "dc01.logging.htb",
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
            "10.129.245.130",
            "dc01.logging.htb",
            previous_ip="10.129.20.182",
        )
    )
    assert "10.129.20.182" in msg
    assert "10.129.245.130" in msg
