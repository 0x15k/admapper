from __future__ import annotations

from pathlib import Path

from admapper.winrm.deps import check_winrm_deps
from admapper.winrm.tickets import write_krb5_conf


def test_write_krb5_conf(tmp_path: Path) -> None:
    path = tmp_path / "krb5.conf"
    write_krb5_conf(path, domain="corp.local", dc_ip="10.0.0.1")
    text = path.read_text()
    assert "CORP.LOCAL" in text
    assert "10.0.0.1" in text


def test_check_winrm_deps_returns_dataclass() -> None:
    deps = check_winrm_deps()
    assert hasattr(deps, "pypsrp")
